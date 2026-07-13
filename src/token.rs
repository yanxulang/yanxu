#[derive(Debug, Clone, PartialEq)]
pub enum TokenKind {
    LeftParen,
    RightParen,
    LeftBracket,
    RightBracket,
    LeftBrace,
    RightBrace,
    Comma,
    Colon,
    Dot,
    Semicolon,
    Plus,
    Minus,
    Star,
    Slash,
    Bang,
    EqualEqual,
    BangEqual,
    Greater,
    GreaterEqual,
    Less,
    LessEqual,
    Identifier(String),
    String(String),
    Number(f64),
    Let,
    Const,
    Set,
    Be,
    Print,
    If,
    Then,
    Else,
    End,
    While,
    For,
    In,
    Function,
    Class,
    This,
    Import,
    As,
    Return,
    Try,
    Catch,
    Throw,
    True,
    False,
    Nil,
    And,
    Or,
    Not,
    Eof,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Token {
    pub kind: TokenKind,
    pub line: usize,
    pub column: usize,
}

impl Token {
    pub fn new(kind: TokenKind, line: usize, column: usize) -> Self {
        Self { kind, line, column }
    }
}
