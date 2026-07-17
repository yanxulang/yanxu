use crate::source::Span;
use crate::token::TokenKind;
use std::fmt;
use std::hash::{Hash, Hasher};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TypePathSegment {
    pub name: String,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TypePath {
    pub segments: Vec<TypePathSegment>,
    pub span: Span,
}

impl TypePath {
    pub fn single(name: impl Into<String>, span: Span) -> Self {
        Self::new(vec![TypePathSegment {
            name: name.into(),
            span,
        }])
    }

    pub fn new(segments: Vec<TypePathSegment>) -> Self {
        debug_assert!(!segments.is_empty());
        let span = segments
            .first()
            .expect("type path has a first segment")
            .span
            .through(&segments.last().expect("type path has a last segment").span);
        Self { segments, span }
    }

    pub fn is_single(&self, name: &str) -> bool {
        matches!(self.segments.as_slice(), [segment] if segment.name == name)
    }

    pub fn single_name(&self) -> Option<&str> {
        match self.segments.as_slice() {
            [segment] => Some(&segment.name),
            _ => None,
        }
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.segments.iter().map(|segment| segment.name.as_str())
    }
}

impl fmt::Display for TypePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, segment) in self.segments.iter().enumerate() {
            if index > 0 {
                formatter.write_str(".")?;
            }
            formatter.write_str(&segment.name)?;
        }
        Ok(())
    }
}

impl Hash for TypePath {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for segment in &self.segments {
            segment.name.hash(state);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TypeKind {
    Named(TypePath),
    Union(Vec<TypeKind>),
    Nullable(Box<TypeKind>),
    Generic {
        base: TypePath,
        arguments: Vec<TypeKind>,
    },
    Function {
        parameters: Vec<TypeKind>,
        result: Box<TypeKind>,
    },
}

impl fmt::Display for TypeKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Named(path) => write!(formatter, "{path}"),
            Self::Union(types) => {
                for (index, ty) in types.iter().enumerate() {
                    if index > 0 {
                        formatter.write_str("|")?;
                    }
                    write!(formatter, "{ty}")?;
                }
                Ok(())
            }
            Self::Nullable(ty) => write!(formatter, "{ty}?"),
            Self::Generic { base, arguments } => {
                write!(formatter, "{base}<")?;
                for (index, argument) in arguments.iter().enumerate() {
                    if index > 0 {
                        formatter.write_str("，")?;
                    }
                    write!(formatter, "{argument}")?;
                }
                formatter.write_str(">")
            }
            Self::Function { parameters, result } => {
                formatter.write_str("法（")?;
                for (index, parameter) in parameters.iter().enumerate() {
                    if index > 0 {
                        formatter.write_str("，")?;
                    }
                    write!(formatter, "{parameter}")?;
                }
                write!(formatter, "）：{result}")
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeRef {
    pub kind: TypeKind,
    /// 稳定的规范拼写，供诊断、文档和旧 API 使用。
    pub name: String,
    pub span: Span,
}

impl TypeRef {
    pub fn new(kind: TypeKind, span: Span) -> Self {
        let name = kind.to_string();
        Self { kind, name, span }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parameter {
    pub name: String,
    pub type_ref: Option<TypeRef>,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum Visibility {
    #[default]
    Public,
    Private,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FieldDecl {
    pub name: String,
    pub type_ref: TypeRef,
    pub initial: Option<Expr>,
    pub visibility: Visibility,
    pub readonly: bool,
    pub is_static: bool,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Literal {
    Number(f64),
    String(String),
    Bool(bool),
    Nil,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Expr {
    pub kind: ExprKind,
    pub span: Span,
}

impl Expr {
    pub fn new(kind: ExprKind, span: Span) -> Self {
        Self { kind, span }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ExprKind {
    Literal(Literal),
    Variable(String),
    This,
    Super {
        method: String,
    },
    List(Vec<Expr>),
    Tuple(Vec<Expr>),
    Map(Vec<(Expr, Expr)>),
    Unary {
        operator: TokenKind,
        right: Box<Expr>,
    },
    Binary {
        left: Box<Expr>,
        operator: TokenKind,
        right: Box<Expr>,
    },
    TypeTest {
        value: Box<Expr>,
        type_ref: TypeRef,
    },
    Call {
        callee: Box<Expr>,
        arguments: Vec<Expr>,
    },
    Get {
        object: Box<Expr>,
        name: String,
    },
    Index {
        object: Box<Expr>,
        index: Box<Expr>,
    },
    Slice {
        object: Box<Expr>,
        start: Option<Box<Expr>>,
        end: Option<Box<Expr>>,
    },
    Await {
        task: Box<Expr>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct Stmt {
    pub kind: StmtKind,
    pub span: Span,
    /// 是否可被其他模块访问。普通顶层执行不受此标记影响。
    pub public: bool,
    /// 类成员属性；顶层声明忽略这两个字段。
    pub member_visibility: Visibility,
    pub is_static: bool,
}

impl Stmt {
    pub fn new(kind: StmtKind, span: Span) -> Self {
        Self {
            kind,
            span,
            public: false,
            member_visibility: Visibility::Public,
            is_static: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum StmtKind {
    Let {
        name: String,
        type_ref: Option<TypeRef>,
        value: Expr,
        mutable: bool,
    },
    Set {
        target: Expr,
        value: Expr,
    },
    Print(Expr),
    Expression(Expr),
    If {
        condition: Expr,
        then_branch: Vec<Stmt>,
        else_branch: Vec<Stmt>,
    },
    While {
        condition: Expr,
        body: Vec<Stmt>,
    },
    For {
        name: String,
        type_ref: Option<TypeRef>,
        iterable: Expr,
        body: Vec<Stmt>,
    },
    Function {
        name: String,
        params: Vec<Parameter>,
        return_type: Option<TypeRef>,
        body: Vec<Stmt>,
        is_async: bool,
    },
    Class {
        name: String,
        superclass: Option<TypePath>,
        protocols: Vec<TypePath>,
        fields: Vec<FieldDecl>,
        methods: Vec<Stmt>,
    },
    Protocol {
        name: String,
        fields: Vec<FieldDecl>,
        methods: Vec<Stmt>,
    },
    Import {
        path: String,
        alias: String,
    },
    Try {
        try_branch: Vec<Stmt>,
        error_name: String,
        catch_branch: Vec<Stmt>,
    },
    Throw(Expr),
    Return(Option<Expr>),
}
