use crate::token::TokenKind;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeRef {
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parameter {
    pub name: String,
    pub type_ref: Option<TypeRef>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Literal {
    Number(f64),
    String(String),
    Bool(bool),
    Nil,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Literal(Literal),
    Variable(String),
    This,
    List(Vec<Expr>),
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
}

#[derive(Debug, Clone, PartialEq)]
pub enum Stmt {
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
    },
    Class {
        name: String,
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
