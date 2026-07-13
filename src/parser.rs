use crate::ast::{Expr, Literal, Parameter, Stmt, TypeRef};
use crate::token::{Token, TokenKind};
use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub struct ParseError {
    pub message: String,
    pub line: usize,
    pub column: usize,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "第 {} 行，第 {} 列：{}",
            self.line, self.column, self.message
        )
    }
}

impl std::error::Error for ParseError {}

pub fn parse(tokens: Vec<Token>) -> Result<Vec<Stmt>, ParseError> {
    Parser { tokens, current: 0 }.program()
}

struct Parser {
    tokens: Vec<Token>,
    current: usize,
}

impl Parser {
    fn program(&mut self) -> Result<Vec<Stmt>, ParseError> {
        let mut statements = Vec::new();
        while !self.check(&TokenKind::Eof) {
            statements.push(self.declaration()?);
        }
        Ok(statements)
    }

    fn declaration(&mut self) -> Result<Stmt, ParseError> {
        if self.matches(&TokenKind::Let) {
            return self.let_statement(true);
        }
        if self.matches(&TokenKind::Const) {
            return self.let_statement(false);
        }
        if self.matches(&TokenKind::Function) {
            return self.function_statement();
        }
        if self.matches(&TokenKind::Class) {
            return self.class_statement();
        }
        if self.matches(&TokenKind::Import) {
            return self.import_statement();
        }
        self.statement()
    }

    fn let_statement(&mut self, mutable: bool) -> Result<Stmt, ParseError> {
        let name = self.identifier(if mutable {
            "“令”之后须有变量名"
        } else {
            "“定”之后须有常量名"
        })?;
        let type_ref = self.optional_type_ref()?;
        self.consume(&TokenKind::Be, "变量名之后须有“为”")?;
        let value = self.expression()?;
        self.end_statement()?;
        Ok(Stmt::Let {
            name,
            type_ref,
            value,
            mutable,
        })
    }

    fn function_statement(&mut self) -> Result<Stmt, ParseError> {
        let name = self.identifier("“法”之后须有函数名")?;
        self.consume(&TokenKind::LeftParen, "函数名之后须有左括号")?;
        let mut params = Vec::new();
        if !self.check(&TokenKind::RightParen) {
            loop {
                if params.len() >= 255 {
                    return Err(self.error_here("函数至多可收 255 个参数"));
                }
                let name = self.identifier("此处须有参数名")?;
                let type_ref = self.optional_type_ref()?;
                params.push(Parameter { name, type_ref });
                if !self.matches(&TokenKind::Comma) {
                    break;
                }
            }
        }
        self.consume(&TokenKind::RightParen, "参数之后须有右括号")?;
        let return_type = self.optional_type_ref()?;
        self.consume(&TokenKind::Then, "函数正文之前须有“则”")?;
        let body = self.block_until(&[TokenKind::End])?;
        self.consume(&TokenKind::End, "函数末尾须有“终”")?;
        self.matches(&TokenKind::Semicolon);
        Ok(Stmt::Function {
            name,
            params,
            return_type,
            body,
        })
    }

    fn class_statement(&mut self) -> Result<Stmt, ParseError> {
        let name = self.identifier("“类”之后须有类名")?;
        self.consume(&TokenKind::Then, "类正文之前须有“则”")?;
        let mut methods = Vec::new();
        while !self.check(&TokenKind::End) && !self.check(&TokenKind::Eof) {
            self.consume(&TokenKind::Function, "类正文中只能声明“法”")?;
            methods.push(self.function_statement()?);
        }
        self.consume(&TokenKind::End, "类末尾须有“终”")?;
        self.matches(&TokenKind::Semicolon);
        Ok(Stmt::Class { name, methods })
    }

    fn import_statement(&mut self) -> Result<Stmt, ParseError> {
        let path = match self.advance().kind.clone() {
            TokenKind::String(path) => path,
            _ => return Err(self.error_previous("“引”之后须有文字路径")),
        };
        if !self.matches(&TokenKind::Be) && !self.matches(&TokenKind::As) {
            return Err(self.error_here("模块路径之后须有“为”或“作”"));
        }
        let alias = self.identifier("“为”之后须有模块名")?;
        self.end_statement()?;
        Ok(Stmt::Import { path, alias })
    }

    fn statement(&mut self) -> Result<Stmt, ParseError> {
        if self.matches(&TokenKind::Set) {
            return self.set_statement();
        }
        if self.matches(&TokenKind::Print) {
            return self.print_statement();
        }
        if self.matches(&TokenKind::If) {
            return self.if_statement();
        }
        if self.matches(&TokenKind::While) {
            return self.while_statement();
        }
        if self.matches(&TokenKind::For) {
            return self.for_statement();
        }
        if self.matches(&TokenKind::Try) {
            return self.try_statement();
        }
        if self.matches(&TokenKind::Throw) {
            return self.throw_statement();
        }
        if self.matches(&TokenKind::Return) {
            return self.return_statement();
        }
        let expression = self.expression()?;
        self.end_statement()?;
        Ok(Stmt::Expression(expression))
    }

    fn set_statement(&mut self) -> Result<Stmt, ParseError> {
        let target = self.call()?;
        if !matches!(
            target,
            Expr::Variable(_) | Expr::Get { .. } | Expr::Index { .. }
        ) {
            return Err(self.error_previous("“置”只能改写变量、字段或下标"));
        }
        self.consume(&TokenKind::Be, "改写目标之后须有“为”")?;
        let value = self.expression()?;
        self.end_statement()?;
        Ok(Stmt::Set { target, value })
    }

    fn print_statement(&mut self) -> Result<Stmt, ParseError> {
        let value = self.expression()?;
        self.end_statement()?;
        Ok(Stmt::Print(value))
    }

    fn if_statement(&mut self) -> Result<Stmt, ParseError> {
        let condition = self.expression()?;
        self.consume(&TokenKind::Then, "条件之后须有“则”")?;
        let then_branch = self.block_until(&[TokenKind::Else, TokenKind::End])?;
        let else_branch = if self.matches(&TokenKind::Else) {
            self.block_until(&[TokenKind::End])?
        } else {
            Vec::new()
        };
        self.consume(&TokenKind::End, "判断末尾须有“终”")?;
        self.matches(&TokenKind::Semicolon);
        Ok(Stmt::If {
            condition,
            then_branch,
            else_branch,
        })
    }

    fn while_statement(&mut self) -> Result<Stmt, ParseError> {
        let condition = self.expression()?;
        self.consume(&TokenKind::Then, "循环条件之后须有“则”")?;
        let body = self.block_until(&[TokenKind::End])?;
        self.consume(&TokenKind::End, "循环末尾须有“终”")?;
        self.matches(&TokenKind::Semicolon);
        Ok(Stmt::While { condition, body })
    }

    fn for_statement(&mut self) -> Result<Stmt, ParseError> {
        let name = self.identifier("“逐”之后须有迭代变量名")?;
        let type_ref = self.optional_type_ref()?;
        self.consume(&TokenKind::In, "迭代变量之后须有“于”")?;
        let iterable = self.expression()?;
        self.consume(&TokenKind::Then, "迭代对象之后须有“则”")?;
        let body = self.block_until(&[TokenKind::End])?;
        self.consume(&TokenKind::End, "逐循环末尾须有“终”")?;
        self.matches(&TokenKind::Semicolon);
        Ok(Stmt::For {
            name,
            type_ref,
            iterable,
            body,
        })
    }

    fn try_statement(&mut self) -> Result<Stmt, ParseError> {
        self.consume(&TokenKind::Then, "“试”之后须有“则”")?;
        let try_branch = self.block_until(&[TokenKind::Catch])?;
        self.consume(&TokenKind::Catch, "“试”必须有“救”分支")?;
        let error_name = self.identifier("“救”之后须有错误变量名")?;
        self.consume(&TokenKind::Then, "错误变量之后须有“则”")?;
        let catch_branch = self.block_until(&[TokenKind::End])?;
        self.consume(&TokenKind::End, "“试”语句末尾须有“终”")?;
        self.matches(&TokenKind::Semicolon);
        Ok(Stmt::Try {
            try_branch,
            error_name,
            catch_branch,
        })
    }

    fn throw_statement(&mut self) -> Result<Stmt, ParseError> {
        let value = self.expression()?;
        self.end_statement()?;
        Ok(Stmt::Throw(value))
    }

    fn return_statement(&mut self) -> Result<Stmt, ParseError> {
        let value = if self.check(&TokenKind::Semicolon) {
            None
        } else {
            Some(self.expression()?)
        };
        self.end_statement()?;
        Ok(Stmt::Return(value))
    }

    fn block_until(&mut self, endings: &[TokenKind]) -> Result<Vec<Stmt>, ParseError> {
        let mut statements = Vec::new();
        while !self.check(&TokenKind::Eof) && !endings.iter().any(|kind| self.check(kind)) {
            statements.push(self.declaration()?);
        }
        Ok(statements)
    }

    fn expression(&mut self) -> Result<Expr, ParseError> {
        self.or()
    }

    fn or(&mut self) -> Result<Expr, ParseError> {
        let mut expr = self.and()?;
        while self.matches(&TokenKind::Or) {
            let operator = self.previous().kind.clone();
            let right = self.and()?;
            expr = Expr::Binary {
                left: Box::new(expr),
                operator,
                right: Box::new(right),
            };
        }
        Ok(expr)
    }

    fn and(&mut self) -> Result<Expr, ParseError> {
        let mut expr = self.equality()?;
        while self.matches(&TokenKind::And) {
            let operator = self.previous().kind.clone();
            let right = self.equality()?;
            expr = Expr::Binary {
                left: Box::new(expr),
                operator,
                right: Box::new(right),
            };
        }
        Ok(expr)
    }

    fn equality(&mut self) -> Result<Expr, ParseError> {
        self.binary(
            Self::comparison,
            &[TokenKind::EqualEqual, TokenKind::BangEqual],
        )
    }

    fn comparison(&mut self) -> Result<Expr, ParseError> {
        self.binary(
            Self::term,
            &[
                TokenKind::Greater,
                TokenKind::GreaterEqual,
                TokenKind::Less,
                TokenKind::LessEqual,
            ],
        )
    }

    fn term(&mut self) -> Result<Expr, ParseError> {
        self.binary(Self::factor, &[TokenKind::Plus, TokenKind::Minus])
    }

    fn factor(&mut self) -> Result<Expr, ParseError> {
        self.binary(Self::unary, &[TokenKind::Star, TokenKind::Slash])
    }

    fn binary(
        &mut self,
        next: fn(&mut Self) -> Result<Expr, ParseError>,
        operators: &[TokenKind],
    ) -> Result<Expr, ParseError> {
        let mut expr = next(self)?;
        while operators.iter().any(|kind| self.check(kind)) {
            let operator = self.advance().kind.clone();
            let right = next(self)?;
            expr = Expr::Binary {
                left: Box::new(expr),
                operator,
                right: Box::new(right),
            };
        }
        Ok(expr)
    }

    fn unary(&mut self) -> Result<Expr, ParseError> {
        if self.matches(&TokenKind::Bang)
            || self.matches(&TokenKind::Not)
            || self.matches(&TokenKind::Minus)
        {
            let operator = self.previous().kind.clone();
            let right = self.unary()?;
            return Ok(Expr::Unary {
                operator,
                right: Box::new(right),
            });
        }
        self.call()
    }

    fn call(&mut self) -> Result<Expr, ParseError> {
        let mut expr = self.primary()?;
        loop {
            if self.matches(&TokenKind::LeftParen) {
                let mut arguments = Vec::new();
                if !self.check(&TokenKind::RightParen) {
                    loop {
                        if arguments.len() >= 255 {
                            return Err(self.error_here("一次调用至多可传 255 个参数"));
                        }
                        arguments.push(self.expression()?);
                        if !self.matches(&TokenKind::Comma) {
                            break;
                        }
                    }
                }
                self.consume(&TokenKind::RightParen, "实参之后须有右括号")?;
                expr = Expr::Call {
                    callee: Box::new(expr),
                    arguments,
                };
            } else if self.matches(&TokenKind::Dot) {
                let name = self.identifier("点号之后须有成员名")?;
                expr = Expr::Get {
                    object: Box::new(expr),
                    name,
                };
            } else if self.matches(&TokenKind::LeftBracket) {
                let index = self.expression()?;
                self.consume(&TokenKind::RightBracket, "下标之后须有右方括号")?;
                expr = Expr::Index {
                    object: Box::new(expr),
                    index: Box::new(index),
                };
            } else {
                break;
            }
        }
        Ok(expr)
    }

    fn primary(&mut self) -> Result<Expr, ParseError> {
        if self.check(&TokenKind::Eof) {
            return Err(self.error_here("此处应有数值、文字、变量或括号表达式"));
        }
        let token = self.advance().clone();
        match token.kind {
            TokenKind::False => Ok(Expr::Literal(Literal::Bool(false))),
            TokenKind::True => Ok(Expr::Literal(Literal::Bool(true))),
            TokenKind::Nil => Ok(Expr::Literal(Literal::Nil)),
            TokenKind::Number(value) => Ok(Expr::Literal(Literal::Number(value))),
            TokenKind::String(value) => Ok(Expr::Literal(Literal::String(value))),
            TokenKind::Identifier(name) => Ok(Expr::Variable(name)),
            TokenKind::This => Ok(Expr::This),
            TokenKind::LeftBracket => self.list_literal(),
            TokenKind::LeftBrace => self.map_literal(),
            TokenKind::LeftParen => {
                let expr = self.expression()?;
                self.consume(&TokenKind::RightParen, "表达式之后须有右括号")?;
                Ok(expr)
            }
            _ => Err(ParseError {
                message: "此处应有数值、文字、变量或括号表达式".into(),
                line: token.line,
                column: token.column,
            }),
        }
    }

    fn list_literal(&mut self) -> Result<Expr, ParseError> {
        let mut items = Vec::new();
        if !self.check(&TokenKind::RightBracket) {
            loop {
                items.push(self.expression()?);
                if !self.matches(&TokenKind::Comma) {
                    break;
                }
            }
        }
        self.consume(&TokenKind::RightBracket, "列末尾须有右方括号")?;
        Ok(Expr::List(items))
    }

    fn map_literal(&mut self) -> Result<Expr, ParseError> {
        let mut entries = Vec::new();
        if !self.check(&TokenKind::RightBrace) {
            loop {
                let key = self.expression()?;
                self.consume(&TokenKind::Colon, "典之键后须有冒号")?;
                let value = self.expression()?;
                entries.push((key, value));
                if !self.matches(&TokenKind::Comma) {
                    break;
                }
            }
        }
        self.consume(&TokenKind::RightBrace, "典末尾须有右花括号")?;
        Ok(Expr::Map(entries))
    }

    fn optional_type_ref(&mut self) -> Result<Option<TypeRef>, ParseError> {
        if !self.matches(&TokenKind::Colon) {
            return Ok(None);
        }
        let token = self.advance().clone();
        let name = match token.kind {
            TokenKind::Identifier(name) => name,
            TokenKind::Nil => "空".into(),
            TokenKind::Function => "法".into(),
            TokenKind::Class => "类".into(),
            _ => {
                return Err(ParseError {
                    message: "冒号之后须有类型名".into(),
                    line: token.line,
                    column: token.column,
                });
            }
        };
        Ok(Some(TypeRef { name }))
    }

    fn end_statement(&mut self) -> Result<(), ParseError> {
        self.consume(&TokenKind::Semicolon, "语句末尾须有“；”")?;
        Ok(())
    }

    fn identifier(&mut self, message: &str) -> Result<String, ParseError> {
        let token = self.advance().clone();
        match token.kind {
            TokenKind::Identifier(name) => Ok(name),
            _ => Err(ParseError {
                message: message.into(),
                line: token.line,
                column: token.column,
            }),
        }
    }

    fn consume(&mut self, kind: &TokenKind, message: &str) -> Result<&Token, ParseError> {
        if self.check(kind) {
            return Ok(self.advance());
        }
        Err(self.error_here(message))
    }

    fn matches(&mut self, kind: &TokenKind) -> bool {
        if self.check(kind) {
            self.advance();
            true
        } else {
            false
        }
    }

    fn check(&self, kind: &TokenKind) -> bool {
        std::mem::discriminant(&self.peek().kind) == std::mem::discriminant(kind)
    }

    fn advance(&mut self) -> &Token {
        if !self.check(&TokenKind::Eof) {
            self.current += 1;
        }
        self.previous()
    }

    fn peek(&self) -> &Token {
        &self.tokens[self.current]
    }

    fn previous(&self) -> &Token {
        &self.tokens[self.current.saturating_sub(1)]
    }

    fn error_here(&self, message: impl Into<String>) -> ParseError {
        ParseError {
            message: message.into(),
            line: self.peek().line,
            column: self.peek().column,
        }
    }

    fn error_previous(&self, message: impl Into<String>) -> ParseError {
        ParseError {
            message: message.into(),
            line: self.previous().line,
            column: self.previous().column,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer;

    #[test]
    fn parses_typed_function_and_call() {
        let tokens =
            lexer::scan("法 相加（甲：数，乙：数）：数 则 归 甲 加 乙；终 言 相加（2，3）；")
                .unwrap();
        let statements = parse(tokens).unwrap();
        assert_eq!(statements.len(), 2);
        assert!(
            matches!(&statements[0], Stmt::Function { name, params, .. } if name == "相加" && params.len() == 2)
        );
    }

    #[test]
    fn parses_class_members() {
        let tokens =
            lexer::scan("类 人 则 法 初始化（姓名：文）则 置 此.姓名 为 姓名；终 终").unwrap();
        let statements = parse(tokens).unwrap();
        assert!(
            matches!(&statements[0], Stmt::Class { name, methods } if name == "人" && methods.len() == 1)
        );
    }

    #[test]
    fn parses_data_iteration_and_try() {
        let source = "定 项目：列 为【1，2】；逐 项 于 项目 则 试 则 言 项；救 错 则 抛 错；终 终";
        let statements = parse(lexer::scan(source).unwrap()).unwrap();
        assert_eq!(statements.len(), 2);
        assert!(
            matches!(&statements[1], Stmt::For { body, .. } if matches!(&body[0], Stmt::Try { .. }))
        );
    }
}
