//! 言序 0.6 字节码编译器。
//!
//! 编译结果不保留 AST，也没有解释器回退。法、类、协和模块均降为独立原型；
//! 控制流、异常处理和迭代使用可定位的跳转指令。

use crate::ast::{
    Expr, ExprKind, FieldDecl, Literal, Parameter, Stmt, StmtKind, TypeKind, TypePath, TypeRef,
    Visibility,
};
use crate::source::Span;
use crate::token::TokenKind;
use crate::type_model::{
    ModuleId, RuntimeType, RuntimeTypePath, TypeDeclarationKind, TypeId, TypeLink,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::rc::Rc;

pub const BYTECODE_FORMAT_VERSION: u32 = 2;
const BYTECODE_FORMAT_UNSUPPORTED_CODE: &str = "BYTECODE_FORMAT_UNSUPPORTED";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Constant {
    Number(f64),
    String(String),
    Bool(bool),
    Nil,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParameterSpec {
    pub name: String,
    pub type_ref: Option<RuntimeType>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FunctionPrototype {
    pub name: String,
    pub parameters: Vec<ParameterSpec>,
    pub return_type: Option<RuntimeType>,
    pub chunk: Chunk,
    pub span: Span,
    pub owner_class: Option<TypeId>,
    pub is_static: bool,
    pub is_async: bool,
    pub visibility: Visibility,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FieldPrototype {
    pub name: String,
    pub type_ref: RuntimeType,
    pub visibility: Visibility,
    pub readonly: bool,
    pub is_static: bool,
    pub initial_slot: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClassPrototype {
    pub type_id: TypeId,
    pub superclass: Option<TypeLink>,
    pub protocols: Vec<TypeLink>,
    pub fields: Vec<FieldPrototype>,
    pub methods: Vec<FunctionPrototype>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProtocolPrototype {
    pub type_id: TypeId,
    pub fields: Vec<(String, RuntimeType)>,
    pub methods: Vec<(String, Vec<ParameterSpec>, Option<RuntimeType>)>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Instruction {
    Constant(usize),
    Load(String),
    Define {
        name: String,
        mutable: bool,
        type_ref: Option<RuntimeType>,
    },
    Store(String),
    EnterScope,
    ExitScope,
    Pop,
    Print,
    Negate,
    Not,
    Add,
    Subtract,
    Multiply,
    Divide,
    Equal,
    NotEqual,
    Greater,
    GreaterEqual,
    Less,
    LessEqual,
    BuildList(usize),
    BuildTuple(usize),
    BuildMap(usize),
    Index,
    Slice,
    SetIndex,
    GetProperty(String),
    GetSuper(String),
    SetProperty(String),
    IsType(RuntimeType),
    JumpIfFalse(usize),
    JumpIfTrue(usize),
    Jump(usize),
    MakeClosure(usize),
    Call(usize),
    Await,
    Return,
    GetIterator,
    IteratorNext(usize),
    DefineClass(usize),
    DefineProtocol(usize),
    Import {
        path: String,
        alias: String,
    },
    TryBegin(usize),
    TryEnd,
    BindError(String),
    Throw,
    Halt,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Chunk {
    pub format_version: u32,
    pub module_id: ModuleId,
    pub constants: Vec<Constant>,
    pub code: Vec<Instruction>,
    pub spans: Vec<Span>,
    pub functions: Vec<FunctionPrototype>,
    pub classes: Vec<ClassPrototype>,
    pub protocols: Vec<ProtocolPrototype>,
    pub exports: Vec<String>,
}

impl Chunk {
    fn empty(module_id: ModuleId) -> Self {
        Self {
            format_version: BYTECODE_FORMAT_VERSION,
            module_id,
            constants: Vec::new(),
            code: Vec::new(),
            spans: Vec::new(),
            functions: Vec::new(),
            classes: Vec::new(),
            protocols: Vec::new(),
            exports: Vec::new(),
        }
    }

    pub fn disassemble(&self) -> String {
        let mut output = self
            .code
            .iter()
            .enumerate()
            .map(|(offset, instruction)| format!("{offset:04} {instruction:?}"))
            .collect::<Vec<_>>()
            .join("\n");
        for function in &self.functions {
            output.push_str(&format!(
                "\n\n== 法 {} ==\n{}",
                function.name,
                function.chunk.disassemble()
            ));
        }
        for class in &self.classes {
            for method in &class.methods {
                output.push_str(&format!(
                    "\n\n== {}.{} ==\n{}",
                    class.type_id.name,
                    method.name,
                    method.chunk.disassemble()
                ));
            }
        }
        output
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileError {
    pub message: String,
    pub span: Span,
}

impl fmt::Display for CompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.span.render("编译有误", &self.message))
    }
}

impl std::error::Error for CompileError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveError {
    pub message: String,
}

impl fmt::Display for ArchiveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "字节码归档有误：{}", self.message)
    }
}

impl std::error::Error for ArchiveError {}

pub fn serialize(chunk: &Chunk) -> Result<Vec<u8>, ArchiveError> {
    validate_format(chunk)?;
    serde_json::to_vec(chunk).map_err(|error| archive_error(format!("不能序列化：{error}")))
}

pub fn deserialize(bytes: &[u8]) -> Result<Chunk, ArchiveError> {
    let document: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| archive_error(format!("JSON 无效：{error}")))?;
    let version = document
        .get("format_version")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| archive_error("缺少整数 format_version"))?;
    if version != u64::from(BYTECODE_FORMAT_VERSION) {
        return Err(unsupported_format_error(version));
    }
    let chunk: Chunk = serde_json::from_value(document)
        .map_err(|error| archive_error(format!("结构无效：{error}")))?;
    validate_format(&chunk)?;
    Ok(chunk)
}

pub fn validate_format(chunk: &Chunk) -> Result<(), ArchiveError> {
    validate_chunk(chunk, None)
}

fn validate_chunk(chunk: &Chunk, parent_module: Option<&ModuleId>) -> Result<(), ArchiveError> {
    if chunk.format_version != BYTECODE_FORMAT_VERSION {
        return Err(unsupported_format_error(u64::from(chunk.format_version)));
    }
    if !chunk.module_id.is_valid() {
        return Err(archive_error(format!(
            "无效的规范模块身份：{}",
            chunk.module_id
        )));
    }
    if parent_module.is_some_and(|module| module != &chunk.module_id) {
        return Err(archive_error(format!(
            "嵌套字节码模块身份 {} 与外层 {} 不一致",
            chunk.module_id,
            parent_module.expect("parent module checked above")
        )));
    }
    for instruction in &chunk.code {
        match instruction {
            Instruction::Define {
                type_ref: Some(ty), ..
            }
            | Instruction::IsType(ty) => validate_runtime_type(ty)?,
            _ => {}
        }
    }
    for function in &chunk.functions {
        validate_function(function, &chunk.module_id, None)?;
    }
    for class in &chunk.classes {
        validate_type_id(&class.type_id, TypeDeclarationKind::Class, &chunk.module_id)?;
        if let Some(superclass) = &class.superclass {
            validate_type_link(superclass, Some(TypeDeclarationKind::Class))?;
        }
        for protocol in &class.protocols {
            validate_type_link(protocol, Some(TypeDeclarationKind::Protocol))?;
        }
        for field in &class.fields {
            validate_runtime_type(&field.type_ref)?;
        }
        for method in &class.methods {
            validate_function(method, &chunk.module_id, Some(&class.type_id))?;
        }
    }
    for protocol in &chunk.protocols {
        validate_type_id(
            &protocol.type_id,
            TypeDeclarationKind::Protocol,
            &chunk.module_id,
        )?;
        for (_, ty) in &protocol.fields {
            validate_runtime_type(ty)?;
        }
        for (_, parameters, return_type) in &protocol.methods {
            for parameter in parameters {
                if let Some(ty) = &parameter.type_ref {
                    validate_runtime_type(ty)?;
                }
            }
            if let Some(ty) = return_type {
                validate_runtime_type(ty)?;
            }
        }
    }
    Ok(())
}

fn validate_function(
    function: &FunctionPrototype,
    module_id: &ModuleId,
    expected_owner: Option<&TypeId>,
) -> Result<(), ArchiveError> {
    if function.owner_class.as_ref() != expected_owner {
        return Err(archive_error(format!(
            "法“{}”的类型所有者身份无效",
            function.name
        )));
    }
    for parameter in &function.parameters {
        if let Some(ty) = &parameter.type_ref {
            validate_runtime_type(ty)?;
        }
    }
    if let Some(ty) = &function.return_type {
        validate_runtime_type(ty)?;
    }
    validate_chunk(&function.chunk, Some(module_id))
}

fn validate_type_id(
    type_id: &TypeId,
    expected_kind: TypeDeclarationKind,
    module_id: &ModuleId,
) -> Result<(), ArchiveError> {
    if !type_id.is_valid() || type_id.kind != expected_kind || &type_id.module != module_id {
        return Err(archive_error(format!("无效的规范类型身份：{type_id}")));
    }
    Ok(())
}

fn validate_type_link(
    link: &TypeLink,
    expected_kind: Option<TypeDeclarationKind>,
) -> Result<(), ArchiveError> {
    if !link.is_valid()
        || expected_kind.is_some_and(|kind| link.target.as_ref().is_some_and(|id| id.kind != kind))
    {
        return Err(archive_error(format!("无效的字节码类型链接：{link}")));
    }
    Ok(())
}

fn validate_runtime_type(ty: &RuntimeType) -> Result<(), ArchiveError> {
    if !ty.is_valid() {
        return Err(archive_error(format!("无效的运行时类型：{ty}")));
    }
    Ok(())
}

fn archive_error(message: impl Into<String>) -> ArchiveError {
    ArchiveError {
        message: message.into(),
    }
}

fn unsupported_format_error(detected: u64) -> ArchiveError {
    archive_error(format!(
        "[{BYTECODE_FORMAT_UNSUPPORTED_CODE}] 检测到字节码格式 {detected}；当前支持字节码格式 {BYTECODE_FORMAT_VERSION}；安全自动迁移：否。请用当前言序从源码重新编译"
    ))
}

pub fn compile(statements: &[Stmt]) -> Result<Chunk, CompileError> {
    let module_id = statements
        .first()
        .map(|statement| ModuleId::for_source(&statement.span.source.name))
        .unwrap_or_else(|| ModuleId::for_source("<空模块>"));
    compile_with_module_id(statements, module_id)
}

pub fn compile_with_module_id(
    statements: &[Stmt],
    module_id: ModuleId,
) -> Result<Chunk, CompileError> {
    let fallback_span = statements
        .first()
        .map(|statement| statement.span.clone())
        .unwrap_or_else(Span::synthetic);
    if !module_id.is_valid() {
        return Err(CompileError {
            message: format!("无效的规范模块身份：{module_id}"),
            span: fallback_span,
        });
    }
    let local_types = Rc::new(local_type_ids(statements, &module_id));
    let mut compiler = Compiler::new(module_id, local_types);
    for statement in statements {
        compiler.statement(statement)?;
        if statement.public {
            let export = match &statement.kind {
                StmtKind::Import { alias, .. } => Some(alias.as_str()),
                _ => declared_name(statement),
            };
            if let Some(name) = export {
                compiler.chunk.exports.push(name.into());
            }
        }
    }
    let span = statements
        .last()
        .map(|statement| statement.span.clone())
        .unwrap_or_else(Span::synthetic);
    compiler.emit(Instruction::Halt, span);
    Ok(compiler.chunk)
}

struct Compiler {
    chunk: Chunk,
    local_types: Rc<BTreeMap<String, TypeId>>,
}

impl Compiler {
    fn new(module_id: ModuleId, local_types: Rc<BTreeMap<String, TypeId>>) -> Self {
        Self {
            chunk: Chunk::empty(module_id),
            local_types,
        }
    }

    fn runtime_type(&self, type_ref: &TypeRef) -> RuntimeType {
        runtime_type(&type_ref.kind, &self.local_types)
    }

    fn type_link(&self, path: &TypePath) -> TypeLink {
        type_link(path, &self.local_types)
    }

    fn compile_function(
        &self,
        statement: &Stmt,
        owner_class: Option<TypeId>,
    ) -> Result<FunctionPrototype, CompileError> {
        let StmtKind::Function {
            name,
            params,
            return_type,
            body,
            is_async,
        } = &statement.kind
        else {
            unreachable!("only function statements are compiled as functions")
        };
        let mut compiler = Compiler::new(self.chunk.module_id.clone(), self.local_types.clone());
        for child in body {
            compiler.statement(child)?;
        }
        let index = compiler.constant(Constant::Nil);
        compiler.emit(Instruction::Constant(index), statement.span.clone());
        compiler.emit(Instruction::Return, statement.span.clone());
        Ok(FunctionPrototype {
            name: name.clone(),
            parameters: parameter_specs(params, &self.local_types),
            return_type: return_type.as_ref().map(|ty| self.runtime_type(ty)),
            chunk: compiler.chunk,
            span: statement.span.clone(),
            owner_class,
            is_static: statement.is_static,
            is_async: *is_async,
            visibility: statement.member_visibility,
        })
    }

    fn statement(&mut self, statement: &Stmt) -> Result<(), CompileError> {
        match &statement.kind {
            StmtKind::Let {
                name,
                type_ref,
                value,
                mutable,
            } => {
                self.expression(value)?;
                self.emit(
                    Instruction::Define {
                        name: name.clone(),
                        mutable: *mutable,
                        type_ref: type_ref.as_ref().map(|ty| self.runtime_type(ty)),
                    },
                    statement.span.clone(),
                );
            }
            StmtKind::Set { target, value } => match &target.kind {
                ExprKind::Variable(name) => {
                    self.expression(value)?;
                    self.emit(Instruction::Store(name.clone()), statement.span.clone());
                }
                ExprKind::Get { object, name } => {
                    self.expression(object)?;
                    self.expression(value)?;
                    self.emit(
                        Instruction::SetProperty(name.clone()),
                        statement.span.clone(),
                    );
                }
                ExprKind::Index { object, index } => {
                    self.expression(object)?;
                    self.expression(index)?;
                    self.expression(value)?;
                    self.emit(Instruction::SetIndex, statement.span.clone());
                }
                _ => unreachable!("parser permits only assignable targets"),
            },
            StmtKind::Print(expression) => {
                self.expression(expression)?;
                self.emit(Instruction::Print, statement.span.clone());
            }
            StmtKind::Expression(expression) => {
                self.expression(expression)?;
                self.emit(Instruction::Pop, statement.span.clone());
            }
            StmtKind::If {
                condition,
                then_branch,
                else_branch,
            } => {
                self.expression(condition)?;
                let false_jump = self.emit_jump(false, statement.span.clone());
                self.emit(Instruction::Pop, condition.span.clone());
                self.scoped_block(then_branch, statement.span.clone())?;
                let end_jump = self.emit_jump_always(statement.span.clone());
                self.patch(false_jump);
                self.emit(Instruction::Pop, condition.span.clone());
                self.scoped_block(else_branch, statement.span.clone())?;
                self.patch(end_jump);
            }
            StmtKind::While { condition, body } => {
                let loop_start = self.chunk.code.len();
                self.expression(condition)?;
                let exit_jump = self.emit_jump(false, statement.span.clone());
                self.emit(Instruction::Pop, condition.span.clone());
                self.scoped_block(body, statement.span.clone())?;
                self.emit(Instruction::Jump(loop_start), statement.span.clone());
                self.patch(exit_jump);
                self.emit(Instruction::Pop, condition.span.clone());
            }
            StmtKind::For {
                name,
                type_ref,
                iterable,
                body,
            } => {
                self.expression(iterable)?;
                self.emit(Instruction::GetIterator, iterable.span.clone());
                let loop_start = self.chunk.code.len();
                let next = self.emit(
                    Instruction::IteratorNext(usize::MAX),
                    statement.span.clone(),
                );
                self.emit(Instruction::EnterScope, statement.span.clone());
                self.emit(
                    Instruction::Define {
                        name: name.clone(),
                        mutable: false,
                        type_ref: type_ref.as_ref().map(|ty| self.runtime_type(ty)),
                    },
                    statement.span.clone(),
                );
                for child in body {
                    self.statement(child)?;
                }
                self.emit(Instruction::ExitScope, statement.span.clone());
                self.emit(Instruction::Jump(loop_start), statement.span.clone());
                self.patch(next);
            }
            StmtKind::Function { name, .. } => {
                let prototype = self.compile_function(statement, None)?;
                let index = self.chunk.functions.len();
                self.chunk.functions.push(prototype);
                self.emit(Instruction::MakeClosure(index), statement.span.clone());
                self.emit(
                    Instruction::Define {
                        name: name.clone(),
                        mutable: false,
                        type_ref: Some(RuntimeType::named("法")),
                    },
                    statement.span.clone(),
                );
            }
            StmtKind::Class {
                name,
                superclass,
                protocols,
                fields,
                methods,
            } => {
                let type_id = self
                    .local_types
                    .get(name)
                    .cloned()
                    .expect("local class identity was precomputed");
                let mut initial_slot = 0;
                let field_prototypes = fields
                    .iter()
                    .map(|field| {
                        let slot = field.initial.as_ref().map(|_| {
                            let slot = initial_slot;
                            initial_slot += 1;
                            slot
                        });
                        field_prototype(field, slot, &self.local_types)
                    })
                    .collect::<Vec<_>>();
                for field in fields {
                    if let Some(initial) = &field.initial {
                        self.expression(initial)?;
                    }
                }
                let method_prototypes = methods
                    .iter()
                    .map(|method| self.compile_function(method, Some(type_id.clone())))
                    .collect::<Result<Vec<_>, _>>()?;
                let index = self.chunk.classes.len();
                self.chunk.classes.push(ClassPrototype {
                    type_id,
                    superclass: superclass.as_ref().map(|path| self.type_link(path)),
                    protocols: protocols.iter().map(|path| self.type_link(path)).collect(),
                    fields: field_prototypes,
                    methods: method_prototypes,
                });
                self.emit(Instruction::DefineClass(index), statement.span.clone());
            }
            StmtKind::Protocol {
                name,
                fields,
                methods,
            } => {
                let type_id = self
                    .local_types
                    .get(name)
                    .cloned()
                    .expect("local protocol identity was precomputed");
                let methods = methods
                    .iter()
                    .map(|method| {
                        let StmtKind::Function {
                            name,
                            params,
                            return_type,
                            ..
                        } = &method.kind
                        else {
                            unreachable!("protocol contains function signatures")
                        };
                        (
                            name.clone(),
                            parameter_specs(params, &self.local_types),
                            return_type.as_ref().map(|ty| self.runtime_type(ty)),
                        )
                    })
                    .collect();
                let index = self.chunk.protocols.len();
                self.chunk.protocols.push(ProtocolPrototype {
                    type_id,
                    fields: fields
                        .iter()
                        .map(|field| (field.name.clone(), self.runtime_type(&field.type_ref)))
                        .collect(),
                    methods,
                });
                self.emit(Instruction::DefineProtocol(index), statement.span.clone());
            }
            StmtKind::Import { path, alias } => {
                self.emit(
                    Instruction::Import {
                        path: path.clone(),
                        alias: alias.clone(),
                    },
                    statement.span.clone(),
                );
            }
            StmtKind::Try {
                try_branch,
                error_name,
                catch_branch,
            } => {
                self.emit(Instruction::EnterScope, statement.span.clone());
                let handler = self.emit(Instruction::TryBegin(usize::MAX), statement.span.clone());
                for child in try_branch {
                    self.statement(child)?;
                }
                self.emit(Instruction::TryEnd, statement.span.clone());
                self.emit(Instruction::ExitScope, statement.span.clone());
                let end = self.emit_jump_always(statement.span.clone());
                self.patch(handler);
                self.emit(
                    Instruction::BindError(error_name.clone()),
                    statement.span.clone(),
                );
                for child in catch_branch {
                    self.statement(child)?;
                }
                self.emit(Instruction::ExitScope, statement.span.clone());
                self.patch(end);
            }
            StmtKind::Throw(expression) => {
                self.expression(expression)?;
                self.emit(Instruction::Throw, statement.span.clone());
            }
            StmtKind::Return(expression) => {
                if let Some(expression) = expression {
                    self.expression(expression)?;
                } else {
                    self.nil(statement.span.clone());
                }
                self.emit(Instruction::Return, statement.span.clone());
            }
        }
        Ok(())
    }

    fn scoped_block(&mut self, statements: &[Stmt], span: Span) -> Result<(), CompileError> {
        self.emit(Instruction::EnterScope, span.clone());
        for statement in statements {
            self.statement(statement)?;
        }
        self.emit(Instruction::ExitScope, span);
        Ok(())
    }

    fn expression(&mut self, expression: &Expr) -> Result<(), CompileError> {
        match &expression.kind {
            ExprKind::Literal(literal) => {
                let value = match literal {
                    Literal::Number(value) => Constant::Number(*value),
                    Literal::String(value) => Constant::String(value.clone()),
                    Literal::Bool(value) => Constant::Bool(*value),
                    Literal::Nil => Constant::Nil,
                };
                let index = self.constant(value);
                self.emit(Instruction::Constant(index), expression.span.clone());
            }
            ExprKind::Variable(name) => {
                self.emit(Instruction::Load(name.clone()), expression.span.clone());
            }
            ExprKind::This => {
                self.emit(Instruction::Load("此".into()), expression.span.clone());
            }
            ExprKind::Super { method } => {
                self.emit(
                    Instruction::GetSuper(method.clone()),
                    expression.span.clone(),
                );
            }
            ExprKind::List(items) | ExprKind::Tuple(items) => {
                for item in items {
                    self.expression(item)?;
                }
                let instruction = if matches!(expression.kind, ExprKind::List(_)) {
                    Instruction::BuildList(items.len())
                } else {
                    Instruction::BuildTuple(items.len())
                };
                self.emit(instruction, expression.span.clone());
            }
            ExprKind::Map(entries) => {
                for (key, value) in entries {
                    self.expression(key)?;
                    self.expression(value)?;
                }
                self.emit(
                    Instruction::BuildMap(entries.len()),
                    expression.span.clone(),
                );
            }
            ExprKind::Unary { operator, right } => {
                self.expression(right)?;
                self.emit(
                    match operator {
                        TokenKind::Minus => Instruction::Negate,
                        TokenKind::Bang | TokenKind::Not => Instruction::Not,
                        _ => unreachable!("parser limits unary operators"),
                    },
                    expression.span.clone(),
                );
            }
            ExprKind::Binary {
                left,
                operator,
                right,
            } => {
                self.expression(left)?;
                if matches!(operator, TokenKind::And | TokenKind::Or) {
                    let jump =
                        self.emit_jump(matches!(operator, TokenKind::Or), expression.span.clone());
                    self.emit(Instruction::Pop, left.span.clone());
                    self.expression(right)?;
                    self.patch(jump);
                    return Ok(());
                }
                self.expression(right)?;
                self.emit(
                    match operator {
                        TokenKind::Plus => Instruction::Add,
                        TokenKind::Minus => Instruction::Subtract,
                        TokenKind::Star => Instruction::Multiply,
                        TokenKind::Slash => Instruction::Divide,
                        TokenKind::EqualEqual => Instruction::Equal,
                        TokenKind::BangEqual => Instruction::NotEqual,
                        TokenKind::Greater => Instruction::Greater,
                        TokenKind::GreaterEqual => Instruction::GreaterEqual,
                        TokenKind::Less => Instruction::Less,
                        TokenKind::LessEqual => Instruction::LessEqual,
                        _ => unreachable!("parser limits binary operators"),
                    },
                    expression.span.clone(),
                );
            }
            ExprKind::TypeTest { value, type_ref } => {
                self.expression(value)?;
                self.emit(
                    Instruction::IsType(self.runtime_type(type_ref)),
                    expression.span.clone(),
                );
            }
            ExprKind::Call { callee, arguments } => {
                self.expression(callee)?;
                for argument in arguments {
                    self.expression(argument)?;
                }
                self.emit(Instruction::Call(arguments.len()), expression.span.clone());
            }
            ExprKind::Await { task } => {
                self.expression(task)?;
                self.emit(Instruction::Await, expression.span.clone());
            }
            ExprKind::Get { object, name } => {
                self.expression(object)?;
                self.emit(
                    Instruction::GetProperty(name.clone()),
                    expression.span.clone(),
                );
            }
            ExprKind::Index { object, index } => {
                self.expression(object)?;
                self.expression(index)?;
                self.emit(Instruction::Index, expression.span.clone());
            }
            ExprKind::Slice { object, start, end } => {
                self.expression(object)?;
                if let Some(start) = start {
                    self.expression(start)?;
                } else {
                    self.nil(expression.span.clone());
                }
                if let Some(end) = end {
                    self.expression(end)?;
                } else {
                    self.nil(expression.span.clone());
                }
                self.emit(Instruction::Slice, expression.span.clone());
            }
        }
        Ok(())
    }

    fn nil(&mut self, span: Span) {
        let index = self.constant(Constant::Nil);
        self.emit(Instruction::Constant(index), span);
    }

    fn constant(&mut self, value: Constant) -> usize {
        self.chunk.constants.push(value);
        self.chunk.constants.len() - 1
    }

    fn emit(&mut self, instruction: Instruction, span: Span) -> usize {
        self.chunk.code.push(instruction);
        self.chunk.spans.push(span);
        self.chunk.code.len() - 1
    }

    fn emit_jump(&mut self, truthy: bool, span: Span) -> usize {
        self.emit(
            if truthy {
                Instruction::JumpIfTrue(usize::MAX)
            } else {
                Instruction::JumpIfFalse(usize::MAX)
            },
            span,
        )
    }

    fn emit_jump_always(&mut self, span: Span) -> usize {
        self.emit(Instruction::Jump(usize::MAX), span)
    }

    fn patch(&mut self, offset: usize) {
        let target = self.chunk.code.len();
        match &mut self.chunk.code[offset] {
            Instruction::JumpIfFalse(destination)
            | Instruction::JumpIfTrue(destination)
            | Instruction::Jump(destination)
            | Instruction::IteratorNext(destination)
            | Instruction::TryBegin(destination) => *destination = target,
            _ => unreachable!("only patchable instructions are patched"),
        }
    }
}

fn parameter_specs(
    params: &[Parameter],
    local_types: &BTreeMap<String, TypeId>,
) -> Vec<ParameterSpec> {
    params
        .iter()
        .map(|parameter| ParameterSpec {
            name: parameter.name.clone(),
            type_ref: parameter
                .type_ref
                .as_ref()
                .map(|ty| runtime_type(&ty.kind, local_types)),
        })
        .collect()
}

fn field_prototype(
    field: &FieldDecl,
    initial_slot: Option<usize>,
    local_types: &BTreeMap<String, TypeId>,
) -> FieldPrototype {
    FieldPrototype {
        name: field.name.clone(),
        type_ref: runtime_type(&field.type_ref.kind, local_types),
        visibility: field.visibility,
        readonly: field.readonly,
        is_static: field.is_static,
        initial_slot,
    }
}

fn local_type_ids(statements: &[Stmt], module_id: &ModuleId) -> BTreeMap<String, TypeId> {
    statements
        .iter()
        .filter_map(|statement| match &statement.kind {
            StmtKind::Class { name, .. } => Some((
                name.clone(),
                TypeId::new(module_id.clone(), name.clone(), TypeDeclarationKind::Class),
            )),
            StmtKind::Protocol { name, .. } => Some((
                name.clone(),
                TypeId::new(
                    module_id.clone(),
                    name.clone(),
                    TypeDeclarationKind::Protocol,
                ),
            )),
            _ => None,
        })
        .collect()
}

fn runtime_type(kind: &TypeKind, local_types: &BTreeMap<String, TypeId>) -> RuntimeType {
    match kind {
        TypeKind::Named(path) => RuntimeType::Named {
            link: type_link(path, local_types),
        },
        TypeKind::Union(types) => RuntimeType::Union {
            variants: types
                .iter()
                .map(|ty| runtime_type(ty, local_types))
                .collect(),
        },
        TypeKind::Nullable(inner) => RuntimeType::Nullable {
            inner: Box::new(runtime_type(inner, local_types)),
        },
        TypeKind::Generic { base, arguments } => RuntimeType::Generic {
            base: type_link(base, local_types),
            arguments: arguments
                .iter()
                .map(|ty| runtime_type(ty, local_types))
                .collect(),
        },
        TypeKind::Function { parameters, result } => RuntimeType::Function {
            parameters: parameters
                .iter()
                .map(|ty| runtime_type(ty, local_types))
                .collect(),
            result: Box::new(runtime_type(result, local_types)),
        },
    }
}

fn type_link(path: &TypePath, local_types: &BTreeMap<String, TypeId>) -> TypeLink {
    let source = RuntimeTypePath::new(path.names().map(str::to_owned).collect());
    match path
        .single_name()
        .and_then(|name| local_types.get(name))
        .cloned()
    {
        Some(target) => TypeLink::resolved(source, target),
        None => TypeLink::unresolved(source),
    }
}

fn declared_name(statement: &Stmt) -> Option<&str> {
    match &statement.kind {
        StmtKind::Let { name, .. }
        | StmtKind::Function { name, .. }
        | StmtKind::Class { name, .. }
        | StmtKind::Protocol { name, .. } => Some(name),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emits_calls_closures_classes_handlers_and_real_jumps() {
        let source = r#"
            法 加一（值：数）：数 则 归 值 加 1；终
            类 盒 则 域 值：数；法 初始化（值：数）则 置 此.值 为 值；终 终
            试 则 逐 值 于【1，2】则 言 加一（值）；终 救 错 则 言 错；终
        "#;
        let chunk = compile(&crate::parse(source).unwrap()).unwrap();
        assert!(
            chunk
                .code
                .iter()
                .any(|op| matches!(op, Instruction::MakeClosure(_)))
        );
        assert!(
            chunk
                .code
                .iter()
                .any(|op| matches!(op, Instruction::DefineClass(_)))
        );
        assert!(
            chunk
                .code
                .iter()
                .any(|op| matches!(op, Instruction::TryBegin(_)))
        );
        assert!(
            chunk
                .code
                .iter()
                .any(|op| matches!(op, Instruction::IteratorNext(_)))
        );
    }

    #[test]
    fn bytecode_archives_round_trip_and_reject_unknown_versions() {
        let chunk =
            compile(&crate::parse("法 倍（值：数）：数 则 归 值 乘 2；终 言 倍（4）；").unwrap())
                .unwrap();
        let bytes = serialize(&chunk).unwrap();
        let decoded = deserialize(&bytes).unwrap();
        assert_eq!(decoded, chunk);

        let mut document: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        document["format_version"] = serde_json::json!(1);
        let error = deserialize(&serde_json::to_vec(&document).unwrap()).unwrap_err();
        assert!(error.message.contains("检测到字节码格式 1"));
        assert!(error.message.contains(BYTECODE_FORMAT_UNSUPPORTED_CODE));
        assert!(error.message.contains("当前支持字节码格式 2"));
        assert!(error.message.contains("安全自动迁移：否"));
        assert!(deserialize(b"not-json").is_err());
    }

    #[test]
    fn format_two_preserves_canonical_and_source_type_links() {
        let source = r#"
            公 协 可描述 则 法 描述（）：文；终
            公 类 视图 纳 可描述 则
                公 法 描述（）：文 则 归 「视图」；终
            终
            公 类 按钮 承 视图 纳 可描述 则
                域 父项：视图；
                公 法 接受（值：列<视图?>）：视图 则 归 此.父项；终
                公 法 是视图（值：任意）：理 则 归 值 是 视图；终
            终
            公 引「facade.yx」为 门面；
        "#;
        let module_id = ModuleId::archive("app:controls.yx");
        let chunk =
            compile_with_module_id(&crate::parse(source).unwrap(), module_id.clone()).unwrap();
        let view_id = TypeId::new(module_id.clone(), "视图", TypeDeclarationKind::Class);
        let protocol_id = TypeId::new(module_id.clone(), "可描述", TypeDeclarationKind::Protocol);
        let button = chunk
            .classes
            .iter()
            .find(|class| class.type_id.name == "按钮")
            .unwrap();
        assert_eq!(chunk.module_id, module_id);
        assert_eq!(
            button.superclass.as_ref().unwrap().target,
            Some(view_id.clone())
        );
        assert_eq!(button.protocols[0].target, Some(protocol_id));
        assert_eq!(button.fields[0].type_ref.to_string(), "视图");
        let accepts = button
            .methods
            .iter()
            .find(|method| method.name == "接受")
            .unwrap();
        assert_eq!(accepts.owner_class.as_ref(), Some(&button.type_id));
        assert_eq!(
            accepts.parameters[0].type_ref.as_ref().unwrap().to_string(),
            "列<视图?>"
        );
        assert_eq!(accepts.return_type.as_ref().unwrap().to_string(), "视图");
        assert!(button.methods.iter().any(|method| {
            method.chunk.code.iter().any(|instruction| {
                matches!(instruction, Instruction::IsType(RuntimeType::Named { link })
                    if link.target.as_ref() == Some(&view_id))
            })
        }));
        assert!(chunk.exports.contains(&"门面".to_owned()));

        let decoded = deserialize(&serialize(&chunk).unwrap()).unwrap();
        assert_eq!(decoded, chunk);
    }

    #[test]
    fn qualified_links_remain_structured_and_corrupt_identities_are_rejected() {
        let source = r#"
            引「base.yx」为 基础；
            类 按钮 承 基础.视图 纳 基础.可描述 则
                域 内容：典<文，基础.视图?>；
            终
        "#;
        let chunk = compile_with_module_id(
            &crate::parse(source).unwrap(),
            ModuleId::archive("app:controls.yx"),
        )
        .unwrap();
        let class = &chunk.classes[0];
        assert_eq!(
            class.superclass.as_ref().unwrap().source.segments,
            ["基础", "视图"]
        );
        assert!(class.superclass.as_ref().unwrap().target.is_none());
        assert_eq!(class.protocols[0].source.segments, ["基础", "可描述"]);
        assert_eq!(class.fields[0].type_ref.to_string(), "典<文，基础.视图?>");

        let mut document: serde_json::Value =
            serde_json::from_slice(&serialize(&chunk).unwrap()).unwrap();
        document["classes"][0]["type_id"]["name"] = serde_json::json!("");
        let error = deserialize(&serde_json::to_vec(&document).unwrap()).unwrap_err();
        assert!(error.message.contains("无效的规范类型身份"), "{error}");
    }
}
