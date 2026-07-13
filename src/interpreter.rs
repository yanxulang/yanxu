use crate::ast::{Expr, Literal, Parameter, Stmt, TypeRef};
use crate::token::TokenKind;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};

type EnvRef = Rc<RefCell<Environment>>;
type NativeBody = fn(&[Value]) -> Result<Value, RuntimeError>;

#[derive(Clone)]
pub enum Value {
    Number(f64),
    String(String),
    Bool(bool),
    Nil,
    Function(Rc<Function>),
    Native(Rc<NativeFunction>),
    Class(Rc<YanxuClass>),
    Instance(Rc<RefCell<YanxuInstance>>),
    Module(Rc<YanxuModule>),
    List(Rc<RefCell<Vec<Value>>>),
    Map(Rc<RefCell<YanxuMap>>),
    Error(Rc<YanxuErrorValue>),
}

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Number(number) if number.fract() == 0.0 => write!(f, "{number:.0}"),
            Self::Number(number) => write!(f, "{number}"),
            Self::String(text) => write!(f, "{text}"),
            Self::Bool(true) => write!(f, "真"),
            Self::Bool(false) => write!(f, "假"),
            Self::Nil => write!(f, "空"),
            Self::Function(function) => write!(f, "<法 {}>", function.name),
            Self::Native(function) => write!(f, "<天授之法 {}>", function.name),
            Self::Class(class) => write!(f, "<类 {}>", class.name),
            Self::Instance(instance) => write!(f, "<{}之实例>", instance.borrow().class.name),
            Self::Module(module) => write!(f, "<模块 {}>", module.name),
            Self::List(items) => {
                let rendered = items
                    .borrow()
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("，");
                write!(f, "【{rendered}】")
            }
            Self::Map(map) => {
                let rendered = map
                    .borrow()
                    .entries
                    .iter()
                    .map(|(key, value)| format!("{key}：{value}"))
                    .collect::<Vec<_>>()
                    .join("，");
                write!(f, "{{{rendered}}}")
            }
            Self::Error(error) => write!(f, "<误 {}>", error.message),
        }
    }
}

impl Value {
    pub fn type_name(&self) -> String {
        match self {
            Self::Number(_) => "数".into(),
            Self::String(_) => "文".into(),
            Self::Bool(_) => "理".into(),
            Self::Nil => "空".into(),
            Self::Function(_) | Self::Native(_) => "法".into(),
            Self::Class(_) => "类".into(),
            Self::Instance(instance) => instance.borrow().class.name.clone(),
            Self::Module(_) => "模块".into(),
            Self::List(_) => "列".into(),
            Self::Map(_) => "典".into(),
            Self::Error(_) => "误".into(),
        }
    }

    fn truthy(&self) -> bool {
        !matches!(self, Self::Nil | Self::Bool(false))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RuntimeError {
    pub message: String,
    pub frames: Vec<String>,
}

impl RuntimeError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            frames: Vec::new(),
        }
    }

    fn with_frame(mut self, frame: impl Into<String>) -> Self {
        self.frames.push(frame.into());
        self
    }
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)?;
        for frame in &self.frames {
            write!(f, "\n  经 {frame}")?;
        }
        Ok(())
    }
}

impl std::error::Error for RuntimeError {}

#[derive(Clone)]
pub struct Function {
    name: String,
    params: Vec<Parameter>,
    return_type: Option<TypeRef>,
    body: Vec<Stmt>,
    closure: EnvRef,
    module_dir: PathBuf,
}

impl Function {
    fn bind(&self, instance: Rc<RefCell<YanxuInstance>>) -> Self {
        let closure = Environment::child(self.closure.clone());
        closure
            .borrow_mut()
            .define_unchecked("此".into(), Value::Instance(instance), false);
        Self {
            name: self.name.clone(),
            params: self.params.clone(),
            return_type: self.return_type.clone(),
            body: self.body.clone(),
            closure,
            module_dir: self.module_dir.clone(),
        }
    }
}

pub struct NativeFunction {
    name: &'static str,
    arity: usize,
    body: NativeBody,
}

pub struct YanxuClass {
    name: String,
    methods: HashMap<String, Rc<Function>>,
}

impl YanxuClass {
    fn method(&self, name: &str) -> Option<Rc<Function>> {
        self.methods.get(name).cloned()
    }
}

pub struct YanxuInstance {
    class: Rc<YanxuClass>,
    fields: HashMap<String, Value>,
}

pub struct YanxuModule {
    name: String,
    environment: EnvRef,
}

pub struct YanxuMap {
    entries: Vec<(Value, Value)>,
}

pub struct YanxuErrorValue {
    message: String,
    frames: Vec<String>,
}

#[derive(Clone)]
struct Binding {
    value: Value,
    type_ref: Option<TypeRef>,
    mutable: bool,
}

#[derive(Default)]
struct Environment {
    values: HashMap<String, Binding>,
    enclosing: Option<EnvRef>,
}

impl Environment {
    fn child(enclosing: EnvRef) -> EnvRef {
        Rc::new(RefCell::new(Self {
            values: HashMap::new(),
            enclosing: Some(enclosing),
        }))
    }

    fn define(
        &mut self,
        name: String,
        value: Value,
        type_ref: Option<TypeRef>,
        mutable: bool,
    ) -> Result<(), RuntimeError> {
        ensure_type(&format!("变量“{name}”"), type_ref.as_ref(), &value)?;
        self.values.insert(
            name,
            Binding {
                value,
                type_ref,
                mutable,
            },
        );
        Ok(())
    }

    fn define_unchecked(&mut self, name: String, value: Value, mutable: bool) {
        self.values.insert(
            name,
            Binding {
                value,
                type_ref: None,
                mutable,
            },
        );
    }

    fn get(&self, name: &str) -> Result<Value, RuntimeError> {
        if let Some(binding) = self.values.get(name) {
            return Ok(binding.value.clone());
        }
        if let Some(enclosing) = &self.enclosing {
            return enclosing.borrow().get(name);
        }
        Err(RuntimeError::new(format!("未曾定义“{name}”")))
    }

    fn assign(&mut self, name: &str, value: Value) -> Result<(), RuntimeError> {
        if let Some(binding) = self.values.get_mut(name) {
            if !binding.mutable {
                return Err(RuntimeError::new(format!("“{name}”乃定值，不可改写")));
            }
            ensure_type(&format!("变量“{name}”"), binding.type_ref.as_ref(), &value)?;
            binding.value = value;
            return Ok(());
        }
        if let Some(enclosing) = &self.enclosing {
            return enclosing.borrow_mut().assign(name, value);
        }
        Err(RuntimeError::new(format!("不可改写未定义之名“{name}”")))
    }

    fn get_local(&self, name: &str) -> Option<Value> {
        self.values.get(name).map(|binding| binding.value.clone())
    }
}

pub struct Interpreter {
    globals: EnvRef,
    output: Vec<String>,
    echo: bool,
    current_dir: PathBuf,
    module_cache: HashMap<PathBuf, Rc<YanxuModule>>,
    loading_modules: HashSet<PathBuf>,
}

enum Control {
    Continue(Value),
    Return(Value),
}

impl Default for Interpreter {
    fn default() -> Self {
        Self::new()
    }
}

impl Interpreter {
    pub fn new() -> Self {
        Self::with_echo(true)
    }

    pub fn silent() -> Self {
        Self::with_echo(false)
    }

    fn with_echo(echo: bool) -> Self {
        let globals = Rc::new(RefCell::new(Environment::default()));
        define_native(&globals, "时刻", 0, native_clock);
        define_native(&globals, "长度", 1, native_length);
        define_native(&globals, "类型", 1, native_type);
        define_native(&globals, "追加", 2, native_append);
        define_native(&globals, "弹出", 1, native_pop);
        define_native(&globals, "有键", 2, native_has_key);
        Self {
            globals,
            output: Vec::new(),
            echo,
            current_dir: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            module_cache: HashMap::new(),
            loading_modules: HashSet::new(),
        }
    }

    pub fn execute(&mut self, statements: &[Stmt]) -> Result<Value, RuntimeError> {
        self.execute_at(statements, None)
    }

    pub fn execute_in_directory(
        &mut self,
        statements: &[Stmt],
        directory: &Path,
    ) -> Result<Value, RuntimeError> {
        self.execute_at(statements, Some(directory))
    }

    fn execute_at(
        &mut self,
        statements: &[Stmt],
        directory: Option<&Path>,
    ) -> Result<Value, RuntimeError> {
        let previous = directory
            .map(|directory| std::mem::replace(&mut self.current_dir, directory.to_path_buf()));
        let result = match self.execute_statements(statements, self.globals.clone()) {
            Ok(Control::Continue(value)) => Ok(value),
            Ok(Control::Return(_)) => Err(RuntimeError::new("“归”只能用于法之内")),
            Err(error) => Err(error),
        };
        if let Some(previous) = previous {
            self.current_dir = previous;
        }
        result
    }

    pub fn output(&self) -> &[String] {
        &self.output
    }

    pub fn take_output(&mut self) -> Vec<String> {
        std::mem::take(&mut self.output)
    }

    fn execute_statements(
        &mut self,
        statements: &[Stmt],
        env: EnvRef,
    ) -> Result<Control, RuntimeError> {
        let mut last = Value::Nil;
        for statement in statements {
            match self.execute_statement(statement, env.clone())? {
                Control::Continue(value) => last = value,
                returned @ Control::Return(_) => return Ok(returned),
            }
        }
        Ok(Control::Continue(last))
    }

    fn execute_statement(
        &mut self,
        statement: &Stmt,
        env: EnvRef,
    ) -> Result<Control, RuntimeError> {
        match statement {
            Stmt::Let {
                name,
                type_ref,
                value,
                mutable,
            } => {
                let value = self.evaluate(value, env.clone())?;
                env.borrow_mut()
                    .define(name.clone(), value.clone(), type_ref.clone(), *mutable)?;
                Ok(Control::Continue(value))
            }
            Stmt::Set { target, value } => {
                let result = match target {
                    Expr::Variable(name) => {
                        let value = self.evaluate(value, env.clone())?;
                        env.borrow_mut().assign(name, value.clone())?;
                        value
                    }
                    Expr::Get { object, name } => {
                        let object = self.evaluate(object, env.clone())?;
                        let value = self.evaluate(value, env)?;
                        self.set_property(object, name, value.clone())?;
                        value
                    }
                    Expr::Index { object, index } => {
                        let object = self.evaluate(object, env.clone())?;
                        let index = self.evaluate(index, env.clone())?;
                        let value = self.evaluate(value, env)?;
                        self.set_index(object, index, value.clone())?;
                        value
                    }
                    _ => unreachable!("parser only permits assignable targets"),
                };
                Ok(Control::Continue(result))
            }
            Stmt::Print(expr) => {
                let value = self.evaluate(expr, env)?;
                let line = value.to_string();
                if self.echo {
                    println!("{line}");
                }
                self.output.push(line);
                Ok(Control::Continue(value))
            }
            Stmt::Expression(expr) => self.evaluate(expr, env).map(Control::Continue),
            Stmt::If {
                condition,
                then_branch,
                else_branch,
            } => {
                if self.evaluate(condition, env.clone())?.truthy() {
                    self.execute_statements(then_branch, Environment::child(env))
                } else {
                    self.execute_statements(else_branch, Environment::child(env))
                }
            }
            Stmt::While { condition, body } => {
                while self.evaluate(condition, env.clone())?.truthy() {
                    if let returned @ Control::Return(_) =
                        self.execute_statements(body, Environment::child(env.clone()))?
                    {
                        return Ok(returned);
                    }
                }
                Ok(Control::Continue(Value::Nil))
            }
            Stmt::For {
                name,
                type_ref,
                iterable,
                body,
            } => {
                let iterable = self.evaluate(iterable, env.clone())?;
                for item in self.iteration_values(iterable)? {
                    let iteration_env = Environment::child(env.clone());
                    iteration_env.borrow_mut().define(
                        name.clone(),
                        item,
                        type_ref.clone(),
                        false,
                    )?;
                    if let returned @ Control::Return(_) =
                        self.execute_statements(body, iteration_env)?
                    {
                        return Ok(returned);
                    }
                }
                Ok(Control::Continue(Value::Nil))
            }
            Stmt::Function {
                name,
                params,
                return_type,
                body,
            } => {
                let function = self.make_function(name, params, return_type, body, env.clone());
                let value = Value::Function(Rc::new(function));
                env.borrow_mut()
                    .define_unchecked(name.clone(), value.clone(), false);
                Ok(Control::Continue(value))
            }
            Stmt::Class { name, methods } => {
                let mut method_map = HashMap::new();
                for method in methods {
                    let Stmt::Function {
                        name: method_name,
                        params,
                        return_type,
                        body,
                    } = method
                    else {
                        unreachable!("class body only contains methods")
                    };
                    let function =
                        self.make_function(method_name, params, return_type, body, env.clone());
                    method_map.insert(method_name.clone(), Rc::new(function));
                }
                let class = Value::Class(Rc::new(YanxuClass {
                    name: name.clone(),
                    methods: method_map,
                }));
                env.borrow_mut()
                    .define_unchecked(name.clone(), class.clone(), false);
                Ok(Control::Continue(class))
            }
            Stmt::Import { path, alias } => {
                let module = self.load_module(path)?;
                let value = Value::Module(module);
                env.borrow_mut()
                    .define_unchecked(alias.clone(), value.clone(), false);
                Ok(Control::Continue(value))
            }
            Stmt::Try {
                try_branch,
                error_name,
                catch_branch,
            } => match self.execute_statements(try_branch, Environment::child(env.clone())) {
                Ok(control) => Ok(control),
                Err(error) => {
                    let catch_env = Environment::child(env);
                    let error_value = Value::Error(Rc::new(YanxuErrorValue {
                        message: error.message,
                        frames: error.frames,
                    }));
                    catch_env
                        .borrow_mut()
                        .define_unchecked(error_name.clone(), error_value, false);
                    self.execute_statements(catch_branch, catch_env)
                }
            },
            Stmt::Throw(expr) => {
                let value = self.evaluate(expr, env)?;
                match value {
                    Value::Error(error) => Err(RuntimeError {
                        message: error.message.clone(),
                        frames: error.frames.clone(),
                    }),
                    value => Err(RuntimeError::new(value.to_string())),
                }
            }
            Stmt::Return(expr) => {
                let value = match expr {
                    Some(expr) => self.evaluate(expr, env)?,
                    None => Value::Nil,
                };
                Ok(Control::Return(value))
            }
        }
    }

    fn make_function(
        &self,
        name: &str,
        params: &[Parameter],
        return_type: &Option<TypeRef>,
        body: &[Stmt],
        closure: EnvRef,
    ) -> Function {
        Function {
            name: name.into(),
            params: params.to_vec(),
            return_type: return_type.clone(),
            body: body.to_vec(),
            closure,
            module_dir: self.current_dir.clone(),
        }
    }

    fn evaluate(&mut self, expr: &Expr, env: EnvRef) -> Result<Value, RuntimeError> {
        match expr {
            Expr::Literal(literal) => Ok(match literal {
                Literal::Number(value) => Value::Number(*value),
                Literal::String(value) => Value::String(value.clone()),
                Literal::Bool(value) => Value::Bool(*value),
                Literal::Nil => Value::Nil,
            }),
            Expr::Variable(name) => env.borrow().get(name),
            Expr::This => env.borrow().get("此"),
            Expr::List(items) => {
                let values = items
                    .iter()
                    .map(|item| self.evaluate(item, env.clone()))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Value::List(Rc::new(RefCell::new(values))))
            }
            Expr::Map(entries) => {
                let mut map = YanxuMap {
                    entries: Vec::new(),
                };
                for (key, value) in entries {
                    let key = self.evaluate(key, env.clone())?;
                    let value = self.evaluate(value, env.clone())?;
                    map_insert(&mut map, key, value)?;
                }
                Ok(Value::Map(Rc::new(RefCell::new(map))))
            }
            Expr::Unary { operator, right } => {
                let right = self.evaluate(right, env)?;
                match operator {
                    TokenKind::Bang | TokenKind::Not => Ok(Value::Bool(!right.truthy())),
                    TokenKind::Minus => match right {
                        Value::Number(number) => Ok(Value::Number(-number)),
                        value => Err(RuntimeError::new(format!(
                            "不可求负于{}",
                            value.type_name()
                        ))),
                    },
                    _ => unreachable!("parser only creates valid unary operators"),
                }
            }
            Expr::Binary {
                left,
                operator,
                right,
            } => {
                let left = self.evaluate(left, env.clone())?;
                if matches!(operator, TokenKind::Or) && left.truthy() {
                    return Ok(left);
                }
                if matches!(operator, TokenKind::And) && !left.truthy() {
                    return Ok(left);
                }
                let right = self.evaluate(right, env)?;
                self.binary(left, operator, right)
            }
            Expr::Call { callee, arguments } => {
                let callee = self.evaluate(callee, env.clone())?;
                let arguments = arguments
                    .iter()
                    .map(|argument| self.evaluate(argument, env.clone()))
                    .collect::<Result<Vec<_>, _>>()?;
                self.call(callee, arguments)
            }
            Expr::Get { object, name } => {
                let object = self.evaluate(object, env)?;
                self.get_property(object, name)
            }
            Expr::Index { object, index } => {
                let object = self.evaluate(object, env.clone())?;
                let index = self.evaluate(index, env)?;
                self.get_index(object, index)
            }
        }
    }

    fn binary(
        &self,
        left: Value,
        operator: &TokenKind,
        right: Value,
    ) -> Result<Value, RuntimeError> {
        match operator {
            TokenKind::EqualEqual => Ok(Value::Bool(values_equal(&left, &right))),
            TokenKind::BangEqual => Ok(Value::Bool(!values_equal(&left, &right))),
            TokenKind::Plus => match (left, right) {
                (Value::Number(a), Value::Number(b)) => Ok(Value::Number(a + b)),
                (Value::String(a), Value::String(b)) => Ok(Value::String(a + &b)),
                (a, b) => Err(type_pair_error("相加", &a, &b)),
            },
            TokenKind::Minus => numeric_pair(left, right, "相减", |a, b| a - b),
            TokenKind::Star => numeric_pair(left, right, "相乘", |a, b| a * b),
            TokenKind::Slash => {
                if matches!(right, Value::Number(0.0)) {
                    return Err(RuntimeError::new("不可除以零"));
                }
                numeric_pair(left, right, "相除", |a, b| a / b)
            }
            TokenKind::Greater => compare_pair(left, right, "比较", |a, b| a > b),
            TokenKind::GreaterEqual => compare_pair(left, right, "比较", |a, b| a >= b),
            TokenKind::Less => compare_pair(left, right, "比较", |a, b| a < b),
            TokenKind::LessEqual => compare_pair(left, right, "比较", |a, b| a <= b),
            TokenKind::And | TokenKind::Or => Ok(right),
            _ => unreachable!("parser only creates valid binary operators"),
        }
    }

    fn call(&mut self, callee: Value, arguments: Vec<Value>) -> Result<Value, RuntimeError> {
        match callee {
            Value::Function(function) => self.call_function(&function, arguments),
            Value::Native(function) => {
                if arguments.len() != function.arity {
                    return Err(arity_error(function.name, function.arity, arguments.len()));
                }
                (function.body)(&arguments)
                    .map_err(|error| error.with_frame(format!("天授之法“{}”", function.name)))
            }
            Value::Class(class) => {
                let instance = Rc::new(RefCell::new(YanxuInstance {
                    class: class.clone(),
                    fields: HashMap::new(),
                }));
                if let Some(initializer) = class.method("初始化") {
                    let bound = initializer.bind(instance.clone());
                    self.call_function(&bound, arguments)?;
                } else if !arguments.is_empty() {
                    return Err(arity_error(&class.name, 0, arguments.len()));
                }
                Ok(Value::Instance(instance))
            }
            value => Err(RuntimeError::new(format!("{}不可调用", value.type_name()))),
        }
    }

    fn call_function(
        &mut self,
        function: &Function,
        arguments: Vec<Value>,
    ) -> Result<Value, RuntimeError> {
        if arguments.len() != function.params.len() {
            return Err(arity_error(
                &function.name,
                function.params.len(),
                arguments.len(),
            ));
        }
        let env = Environment::child(function.closure.clone());
        let frame = format!("法“{}”", function.name);
        for (parameter, value) in function.params.iter().zip(arguments) {
            env.borrow_mut()
                .define(
                    parameter.name.clone(),
                    value,
                    parameter.type_ref.clone(),
                    true,
                )
                .map_err(|error| error.with_frame(frame.clone()))?;
        }
        let previous = std::mem::replace(&mut self.current_dir, function.module_dir.clone());
        let result = self.execute_statements(&function.body, env);
        self.current_dir = previous;
        let value = match result.map_err(|error| error.with_frame(frame.clone()))? {
            Control::Return(value) => value,
            Control::Continue(_) => Value::Nil,
        };
        ensure_type(
            &format!("法“{}”之归值", function.name),
            function.return_type.as_ref(),
            &value,
        )
        .map_err(|error| error.with_frame(frame))?;
        Ok(value)
    }

    fn get_property(&self, object: Value, name: &str) -> Result<Value, RuntimeError> {
        match object {
            Value::Instance(instance) => {
                if let Some(value) = instance.borrow().fields.get(name).cloned() {
                    return Ok(value);
                }
                let method = instance.borrow().class.method(name);
                method
                    .map(|method| Value::Function(Rc::new(method.bind(instance.clone()))))
                    .ok_or_else(|| RuntimeError::new(format!("实例无成员“{name}”")))
            }
            Value::Module(module) => {
                module.environment.borrow().get_local(name).ok_or_else(|| {
                    RuntimeError::new(format!("模块“{}”未导出“{name}”", module.name))
                })
            }
            Value::Error(error) => match name {
                "消息" => Ok(Value::String(error.message.clone())),
                "踪迹" => Ok(Value::List(Rc::new(RefCell::new(
                    error.frames.iter().cloned().map(Value::String).collect(),
                )))),
                _ => Err(RuntimeError::new(format!("误值无成员“{name}”"))),
            },
            value => Err(RuntimeError::new(format!(
                "{}无可访问之成员“{name}”",
                value.type_name()
            ))),
        }
    }

    fn set_property(&self, object: Value, name: &str, value: Value) -> Result<(), RuntimeError> {
        match object {
            Value::Instance(instance) => {
                instance.borrow_mut().fields.insert(name.into(), value);
                Ok(())
            }
            Value::Module(module) => Err(RuntimeError::new(format!(
                "模块“{}”之成员不可从外部改写",
                module.name
            ))),
            value => Err(RuntimeError::new(format!(
                "{}不可拥有字段“{name}”",
                value.type_name()
            ))),
        }
    }

    fn get_index(&self, object: Value, index: Value) -> Result<Value, RuntimeError> {
        match object {
            Value::List(items) => {
                let index = list_index(&index)?;
                items
                    .borrow()
                    .get(index)
                    .cloned()
                    .ok_or_else(|| RuntimeError::new(format!("列下标 {index} 超出范围")))
            }
            Value::String(text) => {
                let index = list_index(&index)?;
                text.chars()
                    .nth(index)
                    .map(|character| Value::String(character.to_string()))
                    .ok_or_else(|| RuntimeError::new(format!("文字下标 {index} 超出范围")))
            }
            Value::Map(map) => map
                .borrow()
                .entries
                .iter()
                .find(|(key, _)| values_equal(key, &index))
                .map(|(_, value)| value.clone())
                .ok_or_else(|| RuntimeError::new(format!("典中未有键“{index}”"))),
            value => Err(RuntimeError::new(format!(
                "{}不可用下标读取",
                value.type_name()
            ))),
        }
    }

    fn set_index(&self, object: Value, index: Value, value: Value) -> Result<(), RuntimeError> {
        match object {
            Value::List(items) => {
                let index = list_index(&index)?;
                let mut items = items.borrow_mut();
                let slot = items
                    .get_mut(index)
                    .ok_or_else(|| RuntimeError::new(format!("列下标 {index} 超出范围")))?;
                *slot = value;
                Ok(())
            }
            Value::Map(map) => map_insert(&mut map.borrow_mut(), index, value),
            Value::String(_) => Err(RuntimeError::new("文字不可按下标改写")),
            value => Err(RuntimeError::new(format!(
                "{}不可用下标改写",
                value.type_name()
            ))),
        }
    }

    fn iteration_values(&self, value: Value) -> Result<Vec<Value>, RuntimeError> {
        match value {
            Value::List(items) => Ok(items.borrow().clone()),
            Value::String(text) => Ok(text
                .chars()
                .map(|character| Value::String(character.to_string()))
                .collect()),
            Value::Map(map) => Ok(map
                .borrow()
                .entries
                .iter()
                .map(|(key, _)| key.clone())
                .collect()),
            value => Err(RuntimeError::new(format!("{}不可遍历", value.type_name()))),
        }
    }

    fn load_module(&mut self, requested: &str) -> Result<Rc<YanxuModule>, RuntimeError> {
        let requested_path = Path::new(requested);
        let joined = if requested_path.is_absolute() {
            requested_path.to_path_buf()
        } else {
            self.current_dir.join(requested_path)
        };
        let canonical = fs::canonicalize(&joined).map_err(|error| {
            RuntimeError::new(format!("不能载入模块“{}”：{error}", joined.display()))
        })?;

        if let Some(module) = self.module_cache.get(&canonical) {
            return Ok(module.clone());
        }
        if !self.loading_modules.insert(canonical.clone()) {
            return Err(RuntimeError::new(format!(
                "模块循环相引：“{}”",
                canonical.display()
            )));
        }

        let result = self.load_module_uncached(&canonical);
        self.loading_modules.remove(&canonical);
        let module = result?;
        self.module_cache.insert(canonical, module.clone());
        Ok(module)
    }

    fn load_module_uncached(&mut self, path: &Path) -> Result<Rc<YanxuModule>, RuntimeError> {
        let source = fs::read_to_string(path).map_err(|error| {
            RuntimeError::new(format!("不能读取模块“{}”：{error}", path.display()))
        })?;
        let tokens = crate::lexer::scan(&source).map_err(|error| {
            RuntimeError::new(format!("模块“{}”词法有误：{error}", path.display()))
        })?;
        let statements = crate::parser::parse(tokens).map_err(|error| {
            RuntimeError::new(format!("模块“{}”语法有误：{error}", path.display()))
        })?;
        crate::resolver::resolve(&statements).map_err(|error| {
            RuntimeError::new(format!("模块“{}”语义有误：{error}", path.display()))
        })?;

        let module_env = Environment::child(self.globals.clone());
        let directory = path.parent().unwrap_or_else(|| Path::new("."));
        let previous = std::mem::replace(&mut self.current_dir, directory.to_path_buf());
        let execution = self
            .execute_statements(&statements, module_env.clone())
            .map_err(|error| error.with_frame(format!("模块“{}”", path.display())));
        self.current_dir = previous;
        match execution? {
            Control::Return(_) => return Err(RuntimeError::new("模块顶层不可用“归”")),
            Control::Continue(_) => {}
        }

        let name = path
            .file_stem()
            .and_then(|name| name.to_str())
            .unwrap_or("无名")
            .to_owned();
        Ok(Rc::new(YanxuModule {
            name,
            environment: module_env,
        }))
    }
}

fn define_native(env: &EnvRef, name: &'static str, arity: usize, body: NativeBody) {
    env.borrow_mut().define_unchecked(
        name.into(),
        Value::Native(Rc::new(NativeFunction { name, arity, body })),
        false,
    );
}

fn native_clock(_: &[Value]) -> Result<Value, RuntimeError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| RuntimeError::new("无法取得时刻"))?
        .as_secs_f64();
    Ok(Value::Number(seconds))
}

fn native_length(arguments: &[Value]) -> Result<Value, RuntimeError> {
    match &arguments[0] {
        Value::String(text) => Ok(Value::Number(text.chars().count() as f64)),
        Value::List(items) => Ok(Value::Number(items.borrow().len() as f64)),
        Value::Map(map) => Ok(Value::Number(map.borrow().entries.len() as f64)),
        value => Err(RuntimeError::new(format!(
            "“长度”不适用于{}",
            value.type_name()
        ))),
    }
}

fn native_type(arguments: &[Value]) -> Result<Value, RuntimeError> {
    Ok(Value::String(arguments[0].type_name()))
}

fn native_append(arguments: &[Value]) -> Result<Value, RuntimeError> {
    match &arguments[0] {
        Value::List(items) => {
            items.borrow_mut().push(arguments[1].clone());
            Ok(arguments[0].clone())
        }
        value => Err(RuntimeError::new(format!(
            "“追加”不适用于{}",
            value.type_name()
        ))),
    }
}

fn native_pop(arguments: &[Value]) -> Result<Value, RuntimeError> {
    match &arguments[0] {
        Value::List(items) => items
            .borrow_mut()
            .pop()
            .ok_or_else(|| RuntimeError::new("不可从空列弹出")),
        value => Err(RuntimeError::new(format!(
            "“弹出”不适用于{}",
            value.type_name()
        ))),
    }
}

fn native_has_key(arguments: &[Value]) -> Result<Value, RuntimeError> {
    match &arguments[0] {
        Value::Map(map) => Ok(Value::Bool(
            map.borrow()
                .entries
                .iter()
                .any(|(key, _)| values_equal(key, &arguments[1])),
        )),
        value => Err(RuntimeError::new(format!(
            "“有键”不适用于{}",
            value.type_name()
        ))),
    }
}

fn ensure_type(
    subject: &str,
    expected: Option<&TypeRef>,
    value: &Value,
) -> Result<(), RuntimeError> {
    let Some(expected) = expected else {
        return Ok(());
    };
    if value_matches_type(value, &expected.name) {
        return Ok(());
    }
    Err(RuntimeError::new(format!(
        "{subject}注为{}，不可纳入{}",
        expected.name,
        value.type_name()
    )))
}

fn value_matches_type(value: &Value, expected: &str) -> bool {
    match expected {
        "任意" => true,
        "数" => matches!(value, Value::Number(_)),
        "文" => matches!(value, Value::String(_)),
        "理" => matches!(value, Value::Bool(_)),
        "空" => matches!(value, Value::Nil),
        "法" => matches!(value, Value::Function(_) | Value::Native(_)),
        "类" => matches!(value, Value::Class(_)),
        "模块" => matches!(value, Value::Module(_)),
        "对象" => matches!(value, Value::Instance(_)),
        "列" => matches!(value, Value::List(_)),
        "典" => matches!(value, Value::Map(_)),
        "误" => matches!(value, Value::Error(_)),
        class_name => {
            matches!(value, Value::Instance(instance) if instance.borrow().class.name == class_name)
        }
    }
}

fn numeric_pair(
    left: Value,
    right: Value,
    action: &str,
    operation: impl FnOnce(f64, f64) -> f64,
) -> Result<Value, RuntimeError> {
    match (left, right) {
        (Value::Number(a), Value::Number(b)) => Ok(Value::Number(operation(a, b))),
        (a, b) => Err(type_pair_error(action, &a, &b)),
    }
}

fn compare_pair(
    left: Value,
    right: Value,
    action: &str,
    operation: impl FnOnce(f64, f64) -> bool,
) -> Result<Value, RuntimeError> {
    match (left, right) {
        (Value::Number(a), Value::Number(b)) => Ok(Value::Bool(operation(a, b))),
        (a, b) => Err(type_pair_error(action, &a, &b)),
    }
}

fn values_equal(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Nil, Value::Nil) => true,
        (Value::Bool(a), Value::Bool(b)) => a == b,
        (Value::Number(a), Value::Number(b)) => a == b,
        (Value::String(a), Value::String(b)) => a == b,
        (Value::Function(a), Value::Function(b)) => Rc::ptr_eq(a, b),
        (Value::Native(a), Value::Native(b)) => Rc::ptr_eq(a, b),
        (Value::Class(a), Value::Class(b)) => Rc::ptr_eq(a, b),
        (Value::Instance(a), Value::Instance(b)) => Rc::ptr_eq(a, b),
        (Value::Module(a), Value::Module(b)) => Rc::ptr_eq(a, b),
        (Value::List(a), Value::List(b)) => Rc::ptr_eq(a, b),
        (Value::Map(a), Value::Map(b)) => Rc::ptr_eq(a, b),
        (Value::Error(a), Value::Error(b)) => Rc::ptr_eq(a, b),
        _ => false,
    }
}

fn type_pair_error(action: &str, left: &Value, right: &Value) -> RuntimeError {
    RuntimeError::new(format!(
        "不可令{}与{}{}",
        left.type_name(),
        right.type_name(),
        action
    ))
}

fn arity_error(name: &str, expected: usize, actual: usize) -> RuntimeError {
    RuntimeError::new(format!("“{name}”应收 {expected} 个参数，实得 {actual} 个"))
}

fn list_index(value: &Value) -> Result<usize, RuntimeError> {
    match value {
        Value::Number(number) if number.is_finite() && *number >= 0.0 && number.fract() == 0.0 => {
            Ok(*number as usize)
        }
        _ => Err(RuntimeError::new("下标须为非负整数")),
    }
}

fn map_insert(map: &mut YanxuMap, key: Value, value: Value) -> Result<(), RuntimeError> {
    if !matches!(
        key,
        Value::Number(_) | Value::String(_) | Value::Bool(_) | Value::Nil
    ) {
        return Err(RuntimeError::new(format!(
            "{}不可作为典之键",
            key.type_name()
        )));
    }
    if let Some((_, old_value)) = map
        .entries
        .iter_mut()
        .find(|(old_key, _)| values_equal(old_key, &key))
    {
        *old_value = value;
    } else {
        map.entries.push((key, value));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run_with;

    #[test]
    fn runs_loop_and_function() {
        let source = r#"
            法 倍增（数值：数）：数 则
                归 数值 乘 2；
            终
            令 次：数 为 0；
            当 次 小于 3 则
                言 倍增（次）；
                置 次 为 次 加 1；
            终
        "#;
        let mut interpreter = Interpreter::silent();
        run_with(&mut interpreter, source).unwrap();
        assert_eq!(interpreter.output(), &["0", "2", "4"]);
    }

    #[test]
    fn has_lexical_closures() {
        let source = r#"
            法 外层（甲：数）：法 则
                法 内层（乙：数）：数 则 归 甲 加 乙；终
                归 内层；
            终
            令 加十：法 为 外层（10）；
            言 加十（5）；
        "#;
        let mut interpreter = Interpreter::silent();
        run_with(&mut interpreter, source).unwrap();
        assert_eq!(interpreter.output(), &["15"]);
    }

    #[test]
    fn enforces_variable_types() {
        let mut interpreter = Interpreter::silent();
        let error =
            run_with(&mut interpreter, "令 年岁：数 为 18；置 年岁 为「十八」；").unwrap_err();
        assert!(error.to_string().contains("注为数，不可纳入文"));
    }

    #[test]
    fn constructs_instances_and_binds_methods() {
        let source = r#"
            类 人 则
                法 初始化（姓名：文）则 置 此.姓名 为 姓名；终
                法 问候（）：文 则 归 「吾名」 加 此.姓名；终
            终
            令 子：人 为 人（「言序」）；
            言 子.问候（）；
        "#;
        let mut interpreter = Interpreter::silent();
        run_with(&mut interpreter, source).unwrap();
        assert_eq!(interpreter.output(), &["吾名言序"]);
    }

    #[test]
    fn supports_lists_maps_indexes_and_iteration() {
        let source = r#"
            定 人名：列 为 【「甲」，「乙」，「丙」】；
            置 人名【1】 为 「仲」；
            令 次序：典 为 {「甲」：1，「仲」：2，「丙」：3}；
            令 合计：数 为 0；
            逐 姓名：文 于 人名 则
                置 合计 为 合计 加 次序【姓名】；
            终
            言 人名；
            言 合计；
        "#;
        let mut interpreter = Interpreter::silent();
        run_with(&mut interpreter, source).unwrap();
        assert_eq!(interpreter.output(), &["【甲，仲，丙】", "6"]);
    }

    #[test]
    fn catches_structured_errors_with_frames() {
        let source = r#"
            法 内层（）：数 则 归 1 除 0；终
            法 外层（）：数 则 归 内层（）；终
            试 则
                外层（）；
            救 所误 则
                言 所误.消息；
                言 长度（所误.踪迹）；
            终
        "#;
        let mut interpreter = Interpreter::silent();
        run_with(&mut interpreter, source).unwrap();
        assert_eq!(interpreter.output(), &["不可除以零", "2"]);
    }

    #[test]
    fn constants_reject_rebinding_but_allow_collection_mutation() {
        let mut interpreter = Interpreter::silent();
        run_with(
            &mut interpreter,
            "定 数列：列 为【1】；置 数列【0】为 2；言 数列【0】；",
        )
        .unwrap();
        assert_eq!(interpreter.output(), &["2"]);
        let error = run_with(&mut interpreter, "置 数列 为【3】；").unwrap_err();
        assert!(error.to_string().contains("乃定值，不可改写"));
    }
}
