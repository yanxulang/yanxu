use crate::token::{Token, TokenKind};
use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub struct LexError {
    pub message: String,
    pub line: usize,
    pub column: usize,
}

impl fmt::Display for LexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "第 {} 行，第 {} 列：{}",
            self.line, self.column, self.message
        )
    }
}

impl std::error::Error for LexError {}

pub fn scan(source: &str) -> Result<Vec<Token>, LexError> {
    Scanner::new(source).scan_tokens()
}

struct Scanner {
    chars: Vec<char>,
    current: usize,
    line: usize,
    column: usize,
}

impl Scanner {
    fn new(source: &str) -> Self {
        Self {
            chars: source.chars().collect(),
            current: 0,
            line: 1,
            column: 1,
        }
    }

    fn scan_tokens(mut self) -> Result<Vec<Token>, LexError> {
        let mut tokens = Vec::new();
        while !self.at_end() {
            let line = self.line;
            let column = self.column;
            let c = self.advance();
            let kind = match c {
                ' ' | '\t' | '\r' => continue,
                '\n' => continue,
                '(' | '（' => TokenKind::LeftParen,
                ')' | '）' => TokenKind::RightParen,
                '[' | '【' => TokenKind::LeftBracket,
                ']' | '】' => TokenKind::RightBracket,
                '{' => TokenKind::LeftBrace,
                '}' => TokenKind::RightBrace,
                ',' | '，' => TokenKind::Comma,
                ':' | '：' => TokenKind::Colon,
                '.' => TokenKind::Dot,
                ';' | '；' => TokenKind::Semicolon,
                '+' => TokenKind::Plus,
                '-' => TokenKind::Minus,
                '*' | '×' => TokenKind::Star,
                '/' if self.peek() == Some('/') => {
                    while self.peek().is_some_and(|next| next != '\n') {
                        self.advance();
                    }
                    continue;
                }
                '/' | '÷' => TokenKind::Slash,
                '#' => {
                    while self.peek().is_some_and(|next| next != '\n') {
                        self.advance();
                    }
                    continue;
                }
                '!' if self.take_if('=') => TokenKind::BangEqual,
                '!' => TokenKind::Bang,
                '=' if self.take_if('=') => TokenKind::EqualEqual,
                '=' => {
                    return Err(self.error(line, column, "赋值请用“令…为…”或“置…为…”"));
                }
                '>' if self.take_if('=') => TokenKind::GreaterEqual,
                '>' => TokenKind::Greater,
                '<' if self.take_if('=') => TokenKind::LessEqual,
                '<' => TokenKind::Less,
                '"' => TokenKind::String(self.string('"', line, column)?),
                '“' => TokenKind::String(self.string('”', line, column)?),
                '「' => TokenKind::String(self.string('」', line, column)?),
                c if c.is_ascii_digit() => self.number(c, line, column)?,
                c if is_identifier_char(c) => self.identifier(c),
                other => {
                    return Err(self.error(line, column, format!("不识字符“{other}”")));
                }
            };
            tokens.push(Token::new(kind, line, column));
        }
        tokens.push(Token::new(TokenKind::Eof, self.line, self.column));
        Ok(tokens)
    }

    fn string(&mut self, closing: char, line: usize, column: usize) -> Result<String, LexError> {
        let mut value = String::new();
        while let Some(c) = self.peek() {
            if c == closing {
                self.advance();
                return Ok(value);
            }
            if c == '\n' {
                value.push(self.advance());
                continue;
            }
            if c == '\\' {
                self.advance();
                let escaped = self
                    .peek()
                    .ok_or_else(|| self.error(line, column, "字符串未闭合"))?;
                self.advance();
                value.push(match escaped {
                    'n' => '\n',
                    't' => '\t',
                    'r' => '\r',
                    '"' => '"',
                    '\\' => '\\',
                    other => other,
                });
                continue;
            }
            value.push(self.advance());
        }
        Err(self.error(line, column, "字符串未闭合"))
    }

    fn number(&mut self, first: char, line: usize, column: usize) -> Result<TokenKind, LexError> {
        let mut text = first.to_string();
        while self.peek().is_some_and(|c| c.is_ascii_digit()) {
            text.push(self.advance());
        }
        if self.peek() == Some('.') && self.peek_next().is_some_and(|c| c.is_ascii_digit()) {
            text.push(self.advance());
            while self.peek().is_some_and(|c| c.is_ascii_digit()) {
                text.push(self.advance());
            }
        }
        text.parse::<f64>()
            .map(TokenKind::Number)
            .map_err(|_| self.error(line, column, format!("数值“{text}”无效")))
    }

    fn identifier(&mut self, first: char) -> TokenKind {
        let mut text = first.to_string();
        while self.peek().is_some_and(is_identifier_char) {
            text.push(self.advance());
        }
        keyword(&text).unwrap_or(TokenKind::Identifier(text))
    }

    fn advance(&mut self) -> char {
        let c = self.chars[self.current];
        self.current += 1;
        if c == '\n' {
            self.line += 1;
            self.column = 1;
        } else {
            self.column += 1;
        }
        c
    }

    fn take_if(&mut self, expected: char) -> bool {
        if self.peek() == Some(expected) {
            self.advance();
            true
        } else {
            false
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.current).copied()
    }

    fn peek_next(&self) -> Option<char> {
        self.chars.get(self.current + 1).copied()
    }

    fn at_end(&self) -> bool {
        self.current >= self.chars.len()
    }

    fn error(&self, line: usize, column: usize, message: impl Into<String>) -> LexError {
        LexError {
            message: message.into(),
            line,
            column,
        }
    }
}

fn is_identifier_char(c: char) -> bool {
    !c.is_whitespace()
        && !matches!(
            c,
            '(' | ')'
                | '（'
                | '）'
                | '['
                | ']'
                | '【'
                | '】'
                | '{'
                | '}'
                | ','
                | '，'
                | ':'
                | '：'
                | '.'
                | ';'
                | '；'
                | '+'
                | '-'
                | '*'
                | '×'
                | '/'
                | '÷'
                | '!'
                | '='
                | '>'
                | '<'
                | '"'
                | '“'
                | '”'
                | '「'
                | '」'
                | '#'
        )
}

fn keyword(text: &str) -> Option<TokenKind> {
    Some(match text {
        "令" => TokenKind::Let,
        "定" => TokenKind::Const,
        "置" => TokenKind::Set,
        "为" => TokenKind::Be,
        "言" => TokenKind::Print,
        "若" => TokenKind::If,
        "则" => TokenKind::Then,
        "否则" => TokenKind::Else,
        "终" => TokenKind::End,
        "当" => TokenKind::While,
        "逐" => TokenKind::For,
        "于" => TokenKind::In,
        "法" => TokenKind::Function,
        "类" => TokenKind::Class,
        "此" => TokenKind::This,
        "引" => TokenKind::Import,
        "作" => TokenKind::As,
        "归" => TokenKind::Return,
        "试" => TokenKind::Try,
        "救" => TokenKind::Catch,
        "抛" => TokenKind::Throw,
        "真" => TokenKind::True,
        "假" => TokenKind::False,
        "空" => TokenKind::Nil,
        "且" => TokenKind::And,
        "或" => TokenKind::Or,
        "非" => TokenKind::Not,
        "加" => TokenKind::Plus,
        "减" => TokenKind::Minus,
        "乘" => TokenKind::Star,
        "除" => TokenKind::Slash,
        "等于" => TokenKind::EqualEqual,
        "不等于" => TokenKind::BangEqual,
        "大于" => TokenKind::Greater,
        "不小于" | "大于等于" => TokenKind::GreaterEqual,
        "小于" => TokenKind::Less,
        "不大于" | "小于等于" => TokenKind::LessEqual,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scans_chinese_syntax() {
        let tokens = scan("令 年岁 为 18；若 年岁 不小于 18 则 言「已长成」；终").unwrap();
        assert!(
            tokens
                .iter()
                .any(|token| token.kind == TokenKind::GreaterEqual)
        );
        assert!(
            tokens
                .iter()
                .any(|token| token.kind == TokenKind::String("已长成".into()))
        );
    }
}
