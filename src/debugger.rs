//! 可自动化的言序调试适配器。
//!
//! 传输和消息结构遵循 Debug Adapter Protocol 的核心约定，支持初始化、启动、
//! 源码断点、继续、单步、调用栈、作用域变量及断开。调试快照来自参考解释器
//! 的语句执行前钩子，因此不会改变程序求值顺序。

use crate::interpreter::{DebugHook, DebugSnapshot, Interpreter};
use serde_json::{Value, json};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::rc::Rc;

pub fn serve() -> io::Result<()> {
    Protocol::new(BufReader::new(io::stdin()), io::stdout()).serve()
}

struct Protocol<R, W> {
    reader: R,
    writer: W,
    sequence: u64,
    program: Option<PathBuf>,
    breakpoints: HashMap<PathBuf, HashSet<usize>>,
    stop_on_entry: bool,
    step_depth: Option<usize>,
    step_into: bool,
    disconnected: bool,
}

enum RequestAction {
    Continue,
    Start,
    Disconnect,
}

impl<R: BufRead + 'static, W: Write + 'static> Protocol<R, W> {
    fn new(reader: R, writer: W) -> Self {
        Self {
            reader,
            writer,
            sequence: 1,
            program: None,
            breakpoints: HashMap::new(),
            stop_on_entry: false,
            step_depth: None,
            step_into: false,
            disconnected: false,
        }
    }

    fn serve(mut self) -> io::Result<()> {
        while let Some(request) = read_message(&mut self.reader)? {
            match self.handle_top_request(&request)? {
                RequestAction::Continue => {}
                RequestAction::Start => self = self.run_program()?,
                RequestAction::Disconnect => break,
            }
        }
        Ok(())
    }

    fn handle_top_request(&mut self, request: &Value) -> io::Result<RequestAction> {
        let command = request.get("command").and_then(Value::as_str).unwrap_or("");
        match command {
            "initialize" => {
                self.respond(
                    request,
                    json!({
                        "supportsConfigurationDoneRequest": true,
                        "supportsTerminateRequest": true,
                        "supportsEvaluateForHovers": true
                    }),
                )?;
                self.event("initialized", json!({}))?;
            }
            "launch" => {
                let Some(program) = request
                    .pointer("/arguments/program")
                    .and_then(Value::as_str)
                else {
                    self.respond_error(request, "launch 须给出 arguments.program")?;
                    return Ok(RequestAction::Continue);
                };
                self.program = Some(normalize_path(program));
                self.stop_on_entry = request
                    .pointer("/arguments/stopOnEntry")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                self.respond(request, json!({}))?;
            }
            "setBreakpoints" => self.set_breakpoints(request)?,
            "configurationDone" => {
                if self.program.is_none() {
                    self.respond_error(request, "尚未 launch 程序")?;
                } else {
                    self.respond(request, json!({}))?;
                    return Ok(RequestAction::Start);
                }
            }
            "disconnect" | "terminate" => {
                self.respond(request, json!({}))?;
                return Ok(RequestAction::Disconnect);
            }
            _ => self.respond_error(request, "此调试命令尚未支持")?,
        }
        Ok(RequestAction::Continue)
    }

    fn run_program(self) -> io::Result<Self> {
        let program = self.program.clone().expect("checked before run");
        let shared = Rc::new(RefCell::new(self));
        let mut interpreter = Interpreter::silent();
        interpreter.set_debug_hook(Box::new(ProtocolHook {
            protocol: shared.clone(),
        }));
        let result = crate::run_file_with(&mut interpreter, &program);
        interpreter.clear_debug_hook();
        let output = interpreter.take_output();

        let mut protocol = Rc::try_unwrap(shared)
            .map_err(|_| io::Error::other("调试协议仍被占用"))?
            .into_inner();
        for line in output {
            protocol.event(
                "output",
                json!({"category": "stdout", "output": format!("{line}\n")}),
            )?;
        }
        if let Err(error) = result
            && !protocol.disconnected
        {
            protocol.event(
                "output",
                json!({"category": "stderr", "output": format!("{error}\n")}),
            )?;
        }
        if !protocol.disconnected {
            protocol.event("terminated", json!({}))?;
        }
        Ok(protocol)
    }

    fn before_statement(&mut self, snapshot: &DebugSnapshot) -> io::Result<()> {
        if self.disconnected {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "调试已断开"));
        }
        let source = normalize_path(&snapshot.span.source.name);
        let breakpoint = self
            .breakpoints
            .get(&source)
            .is_some_and(|lines| lines.contains(&snapshot.span.line));
        let should_step = self.step_into
            || self
                .step_depth
                .is_some_and(|depth| snapshot.frames.len() <= depth);
        let reason = if self.stop_on_entry {
            self.stop_on_entry = false;
            Some("entry")
        } else if should_step {
            Some("step")
        } else if breakpoint {
            Some("breakpoint")
        } else {
            None
        };
        let Some(reason) = reason else {
            return Ok(());
        };
        self.step_into = false;
        self.step_depth = None;
        self.event(
            "stopped",
            json!({"reason": reason, "threadId": 1, "allThreadsStopped": true}),
        )?;
        self.pause(snapshot)
    }

    fn pause(&mut self, snapshot: &DebugSnapshot) -> io::Result<()> {
        while let Some(request) = read_message(&mut self.reader)? {
            let command = request.get("command").and_then(Value::as_str).unwrap_or("");
            match command {
                "continue" => {
                    self.respond(&request, json!({"allThreadsContinued": true}))?;
                    self.event(
                        "continued",
                        json!({"threadId": 1, "allThreadsContinued": true}),
                    )?;
                    return Ok(());
                }
                "next" => {
                    self.step_depth = Some(snapshot.frames.len());
                    self.respond(&request, json!({}))?;
                    return Ok(());
                }
                "stepIn" => {
                    self.step_into = true;
                    self.respond(&request, json!({}))?;
                    return Ok(());
                }
                "stackTrace" => self.stack_trace(&request, snapshot)?,
                "scopes" => self.scopes(&request, snapshot)?,
                "variables" => self.variables(&request, snapshot)?,
                "evaluate" => self.evaluate(&request, snapshot)?,
                "setBreakpoints" => self.set_breakpoints(&request)?,
                "disconnect" | "terminate" => {
                    self.disconnected = true;
                    self.respond(&request, json!({}))?;
                    return Err(io::Error::new(io::ErrorKind::Interrupted, "调试已断开"));
                }
                _ => self.respond_error(&request, "暂停时不支持此调试命令")?,
            }
        }
        Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "调试客户端已断开",
        ))
    }

    fn stack_trace(&mut self, request: &Value, snapshot: &DebugSnapshot) -> io::Result<()> {
        let frames = snapshot
            .frames
            .iter()
            .map(|frame| {
                json!({
                    "id": frame.id,
                    "name": frame.name,
                    "line": frame.span.line,
                    "column": frame.span.column,
                    "source": source_descriptor(&frame.span.source.name)
                })
            })
            .collect::<Vec<_>>();
        self.respond(
            request,
            json!({"stackFrames": frames, "totalFrames": frames.len()}),
        )
    }

    fn scopes(&mut self, request: &Value, snapshot: &DebugSnapshot) -> io::Result<()> {
        let frame_id = request
            .pointer("/arguments/frameId")
            .and_then(Value::as_u64)
            .unwrap_or(1) as usize;
        let scopes = snapshot
            .frames
            .iter()
            .find(|frame| frame.id == frame_id)
            .map_or_else(Vec::new, |_| {
                vec![json!({
                    "name": "可见变量",
                    "presentationHint": "locals",
                    "variablesReference": frame_id,
                    "expensive": false
                })]
            });
        self.respond(request, json!({"scopes": scopes}))
    }

    fn variables(&mut self, request: &Value, snapshot: &DebugSnapshot) -> io::Result<()> {
        let reference = request
            .pointer("/arguments/variablesReference")
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize;
        let variables = snapshot
            .frames
            .iter()
            .find(|frame| frame.id == reference)
            .map(|frame| {
                frame
                    .variables
                    .iter()
                    .map(|variable| {
                        json!({
                            "name": variable.name,
                            "value": variable.value,
                            "type": variable.type_name,
                            "variablesReference": 0
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        self.respond(request, json!({"variables": variables}))
    }

    fn evaluate(&mut self, request: &Value, snapshot: &DebugSnapshot) -> io::Result<()> {
        let expression = request
            .pointer("/arguments/expression")
            .and_then(Value::as_str)
            .unwrap_or("");
        let variable = snapshot
            .frames
            .iter()
            .flat_map(|frame| &frame.variables)
            .find(|variable| variable.name == expression);
        if let Some(variable) = variable {
            self.respond(
                request,
                json!({
                    "result": variable.value,
                    "type": variable.type_name,
                    "variablesReference": 0
                }),
            )
        } else {
            self.respond_error(request, "当前作用域没有此变量")
        }
    }

    fn set_breakpoints(&mut self, request: &Value) -> io::Result<()> {
        let Some(path) = request
            .pointer("/arguments/source/path")
            .and_then(Value::as_str)
        else {
            return self.respond_error(request, "setBreakpoints 须给出 source.path");
        };
        let path = normalize_path(path);
        let lines = request
            .pointer("/arguments/breakpoints")
            .and_then(Value::as_array)
            .map(|breakpoints| {
                breakpoints
                    .iter()
                    .filter_map(|breakpoint| breakpoint.get("line").and_then(Value::as_u64))
                    .map(|line| line as usize)
                    .collect::<HashSet<_>>()
            })
            .unwrap_or_default();
        let breakpoints = lines
            .iter()
            .map(|line| json!({"verified": true, "line": line, "source": source_descriptor(&path.to_string_lossy())}))
            .collect::<Vec<_>>();
        self.breakpoints.insert(path, lines);
        self.respond(request, json!({"breakpoints": breakpoints}))
    }

    fn respond(&mut self, request: &Value, body: Value) -> io::Result<()> {
        let response = json!({
            "seq": self.next_sequence(),
            "type": "response",
            "request_seq": request.get("seq").and_then(Value::as_u64).unwrap_or(0),
            "success": true,
            "command": request.get("command").and_then(Value::as_str).unwrap_or(""),
            "body": body
        });
        send(&mut self.writer, &response)
    }

    fn respond_error(&mut self, request: &Value, message: &str) -> io::Result<()> {
        let response = json!({
            "seq": self.next_sequence(),
            "type": "response",
            "request_seq": request.get("seq").and_then(Value::as_u64).unwrap_or(0),
            "success": false,
            "command": request.get("command").and_then(Value::as_str).unwrap_or(""),
            "message": message
        });
        send(&mut self.writer, &response)
    }

    fn event(&mut self, event: &str, body: Value) -> io::Result<()> {
        let message = json!({
            "seq": self.next_sequence(),
            "type": "event",
            "event": event,
            "body": body
        });
        send(&mut self.writer, &message)
    }

    fn next_sequence(&mut self) -> u64 {
        let current = self.sequence;
        self.sequence += 1;
        current
    }
}

struct ProtocolHook<R, W> {
    protocol: Rc<RefCell<Protocol<R, W>>>,
}

impl<R: BufRead + 'static, W: Write + 'static> DebugHook for ProtocolHook<R, W> {
    fn before_statement(&mut self, snapshot: &DebugSnapshot) -> Result<(), String> {
        self.protocol
            .borrow_mut()
            .before_statement(snapshot)
            .map_err(|error| error.to_string())
    }
}

fn normalize_path(path: impl AsRef<Path>) -> PathBuf {
    let path = path.as_ref();
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn source_descriptor(path: &str) -> Value {
    if path.starts_with('<') {
        json!({"name": path})
    } else {
        let path = normalize_path(path);
        json!({
            "name": path.file_name().and_then(|name| name.to_str()).unwrap_or("文卷"),
            "path": path
        })
    }
}

fn send(writer: &mut impl Write, value: &Value) -> io::Result<()> {
    let body = serde_json::to_vec(value).map_err(io::Error::other)?;
    write!(writer, "Content-Length: {}\r\n\r\n", body.len())?;
    writer.write_all(&body)?;
    writer.flush()
}

fn read_message(reader: &mut impl BufRead) -> io::Result<Option<Value>> {
    let mut length = None;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header)? == 0 {
            return Ok(None);
        }
        if header == "\r\n" || header == "\n" {
            break;
        }
        if let Some(value) = header
            .strip_prefix("Content-Length:")
            .and_then(|value| value.trim().parse::<usize>().ok())
        {
            length = Some(value);
        }
    }
    let length =
        length.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "缺少 Content-Length"))?;
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    serde_json::from_slice(&body)
        .map(Some)
        .map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn framed(messages: &[Value]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for message in messages {
            let body = serde_json::to_vec(message).unwrap();
            write!(bytes, "Content-Length: {}\r\n\r\n", body.len()).unwrap();
            bytes.extend(body);
        }
        bytes
    }

    #[test]
    fn dap_breakpoint_step_stack_and_variables_are_automatable() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("yanxu-dap-{unique}"));
        fs::create_dir_all(&root).unwrap();
        let program = root.join("调试.yx");
        fs::write(&program, "令 值：数 为 1；\n置 值 为 值 加 1；\n言 值；\n").unwrap();
        let messages = [
            json!({"seq":1,"type":"request","command":"initialize","arguments":{}}),
            json!({"seq":2,"type":"request","command":"launch","arguments":{"program":program}}),
            json!({"seq":3,"type":"request","command":"setBreakpoints","arguments":{"source":{"path":program},"breakpoints":[{"line":2}]}}),
            json!({"seq":4,"type":"request","command":"configurationDone","arguments":{}}),
            json!({"seq":5,"type":"request","command":"stackTrace","arguments":{"threadId":1}}),
            json!({"seq":6,"type":"request","command":"scopes","arguments":{"frameId":1}}),
            json!({"seq":7,"type":"request","command":"variables","arguments":{"variablesReference":1}}),
            json!({"seq":8,"type":"request","command":"next","arguments":{"threadId":1}}),
            json!({"seq":9,"type":"request","command":"continue","arguments":{"threadId":1}}),
            json!({"seq":10,"type":"request","command":"disconnect","arguments":{}}),
        ];
        let reader = Cursor::new(framed(&messages));
        let writer = Cursor::new(Vec::new());
        let protocol = Protocol::new(reader, writer);
        protocol.serve().unwrap();

        // 使用第二个纯内存执行取得响应，便于检查协议文本。
        let reader = Cursor::new(framed(&messages));
        let writer = Rc::new(RefCell::new(Vec::new()));
        struct SharedWriter(Rc<RefCell<Vec<u8>>>);
        impl Write for SharedWriter {
            fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
                self.0.borrow_mut().extend_from_slice(buffer);
                Ok(buffer.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        Protocol::new(reader, SharedWriter(writer.clone()))
            .serve()
            .unwrap();
        let output = String::from_utf8(writer.borrow().clone()).unwrap();
        assert_eq!(output.matches("\"event\":\"stopped\"").count(), 2);
        assert!(output.contains("\"name\":\"值\""));
        assert!(output.contains("\"value\":\"1\""));
        assert!(output.contains("\"event\":\"terminated\""));
        fs::remove_dir_all(root).unwrap();
    }
}
