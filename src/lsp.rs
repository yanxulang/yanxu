//! 言序 Language Server Protocol 实现。
//!
//! 服务以 UTF-16 LSP 坐标对外，语义功能共享 [`crate::semantic::SemanticIndex`]，
//! 包括补全、定义、引用、重命名、悬停和文档符号。

use crate::semantic::{SemanticIndex, Symbol, SymbolKind};
use crate::source::Span;
use crate::token::TokenKind;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::{self, BufRead, Write};

const KEYWORDS: &[&str] = &[
    "令", "定", "置", "为", "言", "若", "则", "否则", "终", "当", "逐", "于", "异", "候", "法",
    "归", "类", "承", "父", "协", "纳", "域", "公", "私", "只", "静", "此", "引", "试", "救", "抛",
    "真", "假", "空", "是", "且", "或", "非",
];

const INTRINSICS: &[(&str, &str)] = &[
    ("时刻", "法（）：数"),
    ("长度", "法（任意）：数"),
    ("类型", "法（任意）：文"),
    ("追加", "法（列<任意>，任意）：列<任意>"),
    ("弹出", "法（列<任意>）：任意"),
    ("有键", "法（典<任意，任意>，任意）：理"),
    ("插入", "法（列<任意>，数，任意）：列<任意>"),
    ("删除", "法（列<任意>，数）：任意"),
    ("键列", "法（典<任意，任意>）：列<任意>"),
    ("值列", "法（典<任意，任意>）：列<任意>"),
    ("遍", "法（任意）：遍器"),
    ("续", "法（遍器）：元<理，任意>"),
    ("范围", "法（数，数）：遍器"),
    ("步进范围", "法（数，数，数）：遍器"),
    ("映射", "法（任意，法）：遍器"),
    ("筛选", "法（任意，法）：遍器"),
    ("折叠", "法（任意，任意，法）：任意"),
    ("排序", "法（任意）：列<任意>"),
    ("反转", "法（任意）：列<任意>"),
    ("包含", "法（任意，任意）：理"),
    ("寻找", "法（任意，法）：元<理，任意>"),
    ("取消", "法（任务<任意>）：理"),
    ("任务状态", "法（任务<任意>）：文"),
    ("并候", "法（列<任务<任意>>）：列<任意>"),
];

pub fn serve() -> io::Result<()> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    serve_io(stdin.lock(), stdout.lock())
}

fn serve_io<R: BufRead, W: Write>(mut reader: R, mut writer: W) -> io::Result<()> {
    let mut documents = HashMap::<String, String>::new();
    while let Some(message) = read_message(&mut reader)? {
        let method = message.get("method").and_then(Value::as_str).unwrap_or("");
        let id = message.get("id").cloned();
        match method {
            "initialize" => respond(&mut writer, id, initialize_result())?,
            "initialized" => {}
            "shutdown" => respond(&mut writer, id, Value::Null)?,
            "exit" => break,
            "textDocument/didOpen" => {
                if let Some(document) = message.pointer("/params/textDocument") {
                    let uri = document.get("uri").and_then(Value::as_str).unwrap_or("");
                    let text = document.get("text").and_then(Value::as_str).unwrap_or("");
                    documents.insert(uri.into(), text.into());
                    publish(&mut writer, uri, text)?;
                }
            }
            "textDocument/didChange" => {
                let uri = document_uri(&message);
                if let Some(text) = message
                    .pointer("/params/contentChanges/0/text")
                    .and_then(Value::as_str)
                {
                    documents.insert(uri.into(), text.into());
                    publish(&mut writer, uri, text)?;
                }
            }
            "textDocument/didClose" => {
                let uri = document_uri(&message);
                documents.remove(uri);
                publish_diagnostics(&mut writer, uri, &[])?;
            }
            "textDocument/formatting" => {
                let uri = document_uri(&message);
                let edits = documents.get(uri).and_then(|source| {
                    crate::parse_named(source, uri).ok().map(|statements| {
                        json!([{
                            "range": full_document_range(source),
                            "newText": crate::formatter::format(&statements)
                        }])
                    })
                });
                respond(&mut writer, id, edits.unwrap_or_else(|| json!([])))?;
            }
            "textDocument/completion"
            | "textDocument/definition"
            | "textDocument/references"
            | "textDocument/prepareRename"
            | "textDocument/rename"
            | "textDocument/hover"
            | "textDocument/documentSymbol" => {
                let uri = document_uri(&message);
                let result = documents.get(uri).map_or(Value::Null, |source| {
                    semantic_response(method, uri, source, &message)
                });
                respond(&mut writer, id, result)?;
            }
            _ if id.is_some() => respond_error(&mut writer, id, -32601, "方法尚未支持")?,
            _ => {}
        }
    }
    Ok(())
}

fn initialize_result() -> Value {
    json!({
        "capabilities": {
            "positionEncoding": "utf-16",
            "textDocumentSync": {"openClose": true, "change": 1},
            "documentFormattingProvider": true,
            "completionProvider": {"triggerCharacters": [".", "："]},
            "definitionProvider": true,
            "referencesProvider": true,
            "renameProvider": {"prepareProvider": true},
            "hoverProvider": true,
            "documentSymbolProvider": true
        },
        "serverInfo": {"name": "yanxu-lsp", "version": env!("CARGO_PKG_VERSION")}
    })
}

fn semantic_response(method: &str, uri: &str, source: &str, request: &Value) -> Value {
    let (line, utf16_column) = request_position(request);
    let column = character_column(source, line, utf16_column);
    let Ok(index) = SemanticIndex::build(source, uri) else {
        return if method == "textDocument/completion" {
            completion_items(
                None,
                line,
                column,
                standard_module_at_completion(source, line, column).as_deref(),
            )
        } else if method == "textDocument/documentSymbol" {
            json!([])
        } else {
            Value::Null
        };
    };
    match method {
        "textDocument/completion" => completion_items(
            Some(&index),
            line,
            column,
            standard_module_at_completion(source, line, column).as_deref(),
        ),
        "textDocument/definition" => definition(&index, uri, source, line, column),
        "textDocument/references" => references(
            &index,
            uri,
            source,
            line,
            column,
            request
                .pointer("/params/context/includeDeclaration")
                .and_then(Value::as_bool)
                .unwrap_or(true),
        ),
        "textDocument/prepareRename" => prepare_rename(&index, source, line, column),
        "textDocument/rename" => rename(&index, uri, source, line, column, request),
        "textDocument/hover" => hover(&index, source, line, column),
        "textDocument/documentSymbol" => document_symbols(&index, source),
        _ => Value::Null,
    }
}

fn completion_items(
    index: Option<&SemanticIndex>,
    line: usize,
    column: usize,
    standard_module: Option<&str>,
) -> Value {
    let mut items = Vec::new();
    if let Some(index) = index {
        for symbol in index.visible_symbols(line, column) {
            items.push(json!({
                "label": symbol.name,
                "kind": symbol.kind.completion_kind(),
                "detail": symbol.detail,
                "documentation": symbol.documentation,
                "sortText": format!("0-{}", symbol.name)
            }));
        }
    }
    for (name, signature) in INTRINSICS {
        items.push(json!({
            "label": name,
            "kind": 3,
            "detail": signature,
            "sortText": format!("1-{name}")
        }));
    }
    if let Some(module_name) = standard_module
        && let Ok(manifest) = crate::stdlib::api_manifest()
        && let Some(module) = manifest["modules"]
            .as_array()
            .and_then(|modules| modules.iter().find(|module| module["name"] == module_name))
        && let Some(members) = module["members"].as_array()
    {
        for member in members {
            let Some(name) = member["name"].as_str() else {
                continue;
            };
            items.push(json!({
                "label": name,
                "kind": if member["kind"] == "constant" { 21 } else { 3 },
                "detail": member["signature"].as_str().unwrap_or("标准库成员"),
                "documentation": format!("标准:{module_name}.{name}"),
                "sortText": format!("0-stdlib-{name}")
            }));
        }
    }
    for keyword in KEYWORDS {
        items.push(json!({
            "label": keyword,
            "kind": 14,
            "detail": "言序关键字",
            "sortText": format!("2-{keyword}")
        }));
    }
    json!({"isIncomplete": false, "items": items})
}

fn standard_module_at_completion(source: &str, line: usize, column: usize) -> Option<String> {
    let prefix = source
        .lines()
        .nth(line.saturating_sub(1))?
        .chars()
        .take(column.saturating_sub(1))
        .collect::<String>();
    let tokens = crate::lexer::scan(&prefix).ok()?;
    let mut kinds = tokens
        .iter()
        .map(|token| &token.kind)
        .filter(|kind| !matches!(kind, TokenKind::Eof))
        .rev();
    if !matches!(kinds.next(), Some(TokenKind::Dot)) {
        return None;
    }
    let Some(TokenKind::Identifier(alias)) = kinds.next() else {
        return None;
    };
    let tokens = crate::lexer::scan(source).ok()?;
    tokens.windows(4).find_map(|tokens| match tokens {
        [
            crate::token::Token {
                kind: TokenKind::Import,
                ..
            },
            crate::token::Token {
                kind: TokenKind::String(path),
                ..
            },
            crate::token::Token {
                kind: TokenKind::Be,
                ..
            },
            crate::token::Token {
                kind: TokenKind::Identifier(candidate),
                ..
            },
        ] if candidate == alias => path.strip_prefix("标准:").map(str::to_owned),
        _ => None,
    })
}

fn definition(index: &SemanticIndex, uri: &str, source: &str, line: usize, column: usize) -> Value {
    index.symbol_at(line, column).map_or(
        Value::Null,
        |symbol| json!({"uri": uri, "range": range(&symbol.selection, source)}),
    )
}

fn references(
    index: &SemanticIndex,
    uri: &str,
    source: &str,
    line: usize,
    column: usize,
    include_declaration: bool,
) -> Value {
    index.symbol_at(line, column).map_or_else(
        || json!([]),
        |symbol| {
            Value::Array(
                index
                    .references(symbol.id, include_declaration)
                    .into_iter()
                    .map(|occurrence| json!({"uri": uri, "range": range(&occurrence.span, source)}))
                    .collect(),
            )
        },
    )
}

fn prepare_rename(index: &SemanticIndex, source: &str, line: usize, column: usize) -> Value {
    index.symbol_at(line, column).map_or(
        Value::Null,
        |symbol| json!({"range": range(&symbol.selection, source), "placeholder": symbol.name}),
    )
}

fn rename(
    index: &SemanticIndex,
    uri: &str,
    source: &str,
    line: usize,
    column: usize,
    request: &Value,
) -> Value {
    let Some(new_name) = request
        .pointer("/params/newName")
        .and_then(Value::as_str)
        .filter(|name| valid_identifier(name))
    else {
        return Value::Null;
    };
    index.symbol_at(line, column).map_or(Value::Null, |symbol| {
        let edits = index
            .references(symbol.id, true)
            .into_iter()
            .map(
                |occurrence| json!({"range": range(&occurrence.span, source), "newText": new_name}),
            )
            .collect::<Vec<_>>();
        json!({"changes": {uri: edits}})
    })
}

fn hover(index: &SemanticIndex, source: &str, line: usize, column: usize) -> Value {
    index.symbol_at(line, column).map_or(Value::Null, |symbol| {
        let mut markdown = format!("```yanxu\n{}\n```", symbol.detail);
        if let Some(documentation) = &symbol.documentation {
            markdown.push_str("\n\n");
            markdown.push_str(documentation);
        }
        json!({
            "contents": {"kind": "markdown", "value": markdown},
            "range": range(&symbol.selection, source)
        })
    })
}

fn document_symbols(index: &SemanticIndex, source: &str) -> Value {
    let top_level = index
        .symbols()
        .iter()
        .filter(|symbol| symbol.container.is_none() && symbol.kind != SymbolKind::Parameter)
        .map(|symbol| {
            let children = index
                .symbols()
                .iter()
                .filter(|child| {
                    child.container.as_deref() == Some(&symbol.name)
                        && matches!(child.kind, SymbolKind::Method | SymbolKind::Field)
                })
                .map(|child| document_symbol(child, source, None))
                .collect::<Vec<_>>();
            document_symbol(symbol, source, (!children.is_empty()).then_some(children))
        })
        .collect::<Vec<_>>();
    Value::Array(top_level)
}

fn document_symbol(symbol: &Symbol, source: &str, children: Option<Vec<Value>>) -> Value {
    let mut value = json!({
        "name": symbol.name,
        "detail": symbol.detail,
        "kind": symbol.kind.lsp_kind(),
        "range": range(&symbol.declaration, source),
        "selectionRange": range(&symbol.selection, source)
    });
    if let Some(children) = children {
        value["children"] = Value::Array(children);
    }
    value
}

pub fn diagnostics(source: &str, name: &str) -> Vec<Value> {
    let statements = match crate::lexer::scan_named(source, name) {
        Err(error) => return vec![diagnostic(&error.span, source, &error.message, 1)],
        Ok(tokens) => match crate::parser::parse(tokens) {
            Err(error) => return vec![diagnostic(&error.span, source, &error.message, 1)],
            Ok(statements) => statements,
        },
    };
    if let Err(error) = crate::resolver::resolve(&statements) {
        return vec![diagnostic(&error.span, source, &error.message, 1)];
    }
    crate::type_checker::check(&statements)
        .err()
        .unwrap_or_default()
        .into_iter()
        .map(|error| diagnostic(&error.span, source, &error.message, 1))
        .collect()
}

fn diagnostic(span: &Span, source: &str, message: &str, severity: u8) -> Value {
    json!({
        "range": range(span, source),
        "severity": severity,
        "source": "言序",
        "message": message
    })
}

fn range(span: &Span, source: &str) -> Value {
    json!({
        "start": {
            "line": span.line.saturating_sub(1),
            "character": utf16_column(source, span.line, span.column)
        },
        "end": {
            "line": span.end_line.saturating_sub(1),
            "character": utf16_column(source, span.end_line, span.end_column)
        }
    })
}

fn full_document_range(source: &str) -> Value {
    let line_count = source.lines().count().max(1);
    let last_line = source.lines().last().unwrap_or("");
    json!({
        "start": {"line": 0, "character": 0},
        "end": {"line": line_count - 1, "character": last_line.encode_utf16().count()}
    })
}

fn utf16_column(source: &str, line: usize, character_column: usize) -> usize {
    source
        .lines()
        .nth(line.saturating_sub(1))
        .unwrap_or("")
        .chars()
        .take(character_column.saturating_sub(1))
        .map(char::len_utf16)
        .sum()
}

fn character_column(source: &str, line: usize, utf16_column: usize) -> usize {
    let mut units = 0;
    let mut characters = 0;
    for character in source
        .lines()
        .nth(line.saturating_sub(1))
        .unwrap_or("")
        .chars()
    {
        if units >= utf16_column {
            break;
        }
        units += character.len_utf16();
        characters += 1;
    }
    characters + 1
}

fn request_position(request: &Value) -> (usize, usize) {
    (
        request
            .pointer("/params/position/line")
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize
            + 1,
        request
            .pointer("/params/position/character")
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize,
    )
}

fn valid_identifier(name: &str) -> bool {
    let Ok(tokens) = crate::lexer::scan(name) else {
        return false;
    };
    matches!(
        tokens.as_slice(),
        [
            crate::token::Token {
                kind: TokenKind::Identifier(value),
                ..
            },
            crate::token::Token {
                kind: TokenKind::Eof,
                ..
            }
        ] if value == name
    )
}

fn document_uri(message: &Value) -> &str {
    message
        .pointer("/params/textDocument/uri")
        .and_then(Value::as_str)
        .unwrap_or("")
}

fn publish(writer: &mut impl Write, uri: &str, source: &str) -> io::Result<()> {
    publish_diagnostics(writer, uri, &diagnostics(source, uri))
}

fn publish_diagnostics(
    writer: &mut impl Write,
    uri: &str,
    diagnostics: &[Value],
) -> io::Result<()> {
    send(
        writer,
        &json!({
            "jsonrpc": "2.0",
            "method": "textDocument/publishDiagnostics",
            "params": {"uri": uri, "diagnostics": diagnostics}
        }),
    )
}

fn respond(writer: &mut impl Write, id: Option<Value>, result: Value) -> io::Result<()> {
    send(
        writer,
        &json!({"jsonrpc": "2.0", "id": id.unwrap_or(Value::Null), "result": result}),
    )
}

fn respond_error(
    writer: &mut impl Write,
    id: Option<Value>,
    code: i32,
    message: &str,
) -> io::Result<()> {
    send(
        writer,
        &json!({
            "jsonrpc": "2.0",
            "id": id.unwrap_or(Value::Null),
            "error": {"code": code, "message": message}
        }),
    )
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

    fn request(method: &str, line: usize, character: usize) -> Value {
        json!({
            "method": method,
            "params": {
                "textDocument": {"uri": "file:///语义.yx"},
                "position": {"line": line, "character": character},
                "context": {"includeDeclaration": true},
                "newName": "相加"
            }
        })
    }

    #[test]
    fn exposes_static_diagnostics_in_utf16_coordinates() {
        let items = diagnostics("定 😀 = 1；", "file:///bad.yx");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["range"]["start"]["character"], 5);
        assert!(items[0]["message"].as_str().unwrap().contains("赋值请用"));
    }

    #[test]
    fn supports_all_semantic_language_features() {
        let source =
            "/// 两数相加。\n法 求和（甲：数，乙：数）：数 则 归 甲 加 乙；终\n言 求和（1，2）；";
        let uri = "file:///语义.yx";

        let completion = semantic_response(
            "textDocument/completion",
            uri,
            source,
            &request("textDocument/completion", 2, 2),
        );
        assert!(
            completion["items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item["label"] == "求和"
                    && item["detail"].as_str().unwrap().contains("数"))
        );
        for keyword in ["父", "是"] {
            assert!(
                completion["items"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|item| item["label"] == keyword && item["kind"] == 14)
            );
        }

        let definition = semantic_response(
            "textDocument/definition",
            uri,
            source,
            &request("textDocument/definition", 2, 3),
        );
        assert_eq!(definition["range"]["start"]["line"], 1);

        let references = semantic_response(
            "textDocument/references",
            uri,
            source,
            &request("textDocument/references", 2, 3),
        );
        assert_eq!(references.as_array().unwrap().len(), 2);

        let renamed = semantic_response(
            "textDocument/rename",
            uri,
            source,
            &request("textDocument/rename", 2, 3),
        );
        assert_eq!(renamed["changes"][uri].as_array().unwrap().len(), 2);

        let hover = semantic_response(
            "textDocument/hover",
            uri,
            source,
            &request("textDocument/hover", 2, 3),
        );
        assert!(
            hover["contents"]["value"]
                .as_str()
                .unwrap()
                .contains("两数相加")
        );

        let symbols = semantic_response(
            "textDocument/documentSymbol",
            uri,
            source,
            &request("textDocument/documentSymbol", 0, 0),
        );
        assert_eq!(symbols[0]["name"], "求和");
    }

    #[test]
    fn completes_versioned_binary_standard_library_members() {
        let source = "引「标准:字节」为 字节；\n字节.";
        assert_eq!(
            standard_module_at_completion(source, 2, 4).as_deref(),
            Some("字节")
        );
        let completion = semantic_response(
            "textDocument/completion",
            "file:///字节.yx",
            source,
            &request("textDocument/completion", 1, 3),
        );
        let items = completion["items"].as_array().unwrap();
        for member in ["从文字", "转文字", "切片", "从数列"] {
            assert!(
                items.iter().any(|item| {
                    item["label"] == member
                        && item["documentation"]
                            .as_str()
                            .is_some_and(|detail| detail.starts_with("标准:字节."))
                }),
                "缺少字节标准库补全：{member}"
            );
        }
    }

    #[test]
    fn announces_semantic_capabilities() {
        let capabilities = initialize_result()["capabilities"].clone();
        assert_eq!(capabilities["definitionProvider"], true);
        assert_eq!(capabilities["renameProvider"]["prepareProvider"], true);
        assert_eq!(capabilities["positionEncoding"], "utf-16");
    }
}
