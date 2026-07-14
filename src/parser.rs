use crate::ast::{
    Expr, ExprKind, FieldDecl, Literal, Parameter, Stmt, StmtKind, TypeKind, TypeRef, Visibility,
};
use crate::source::Span;
use crate::token::{Token, TokenKind};
use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub struct ParseError {
    pub message: String,
    pub line: usize,
    pub column: usize,
    pub span: Span,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.span.render("语法有误", &self.message))
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
        if self.matches(&TokenKind::Public) {
            let public_span = self.previous().span.clone();
            let mut statement = self.declaration()?;
            if !matches!(
                statement.kind,
                StmtKind::Let { .. }
                    | StmtKind::Function { .. }
                    | StmtKind::Class { .. }
                    | StmtKind::Protocol { .. }
            ) {
                return Err(ParseError {
                    message: "“公”只可修饰变量、常量、法、类或协".into(),
                    line: public_span.line,
                    column: public_span.column,
                    span: public_span,
                });
            }
            statement.public = true;
            return Ok(statement);
        }
        if self.matches(&TokenKind::Let) {
            return self.let_statement(self.previous().span.clone(), true);
        }
        if self.matches(&TokenKind::Const) {
            return self.let_statement(self.previous().span.clone(), false);
        }
        if self.matches(&TokenKind::Function) {
            return self.function_statement(self.previous().span.clone(), false);
        }
        if self.matches(&TokenKind::Async) {
            let start = self.previous().span.clone();
            self.consume(&TokenKind::Function, "“异”之后须有“法”")?;
            return self.function_statement(start, true);
        }
        if self.matches(&TokenKind::Class) {
            return self.class_statement(self.previous().span.clone());
        }
        if self.matches(&TokenKind::Protocol) {
            return self.protocol_statement(self.previous().span.clone());
        }
        if self.matches(&TokenKind::Import) {
            return self.import_statement(self.previous().span.clone());
        }
        self.statement()
    }

    fn let_statement(&mut self, start: Span, mutable: bool) -> Result<Stmt, ParseError> {
        let (name, _) = self.identifier_token(if mutable {
            "“令”之后须有变量名"
        } else {
            "“定”之后须有常量名"
        })?;
        let type_ref = self.optional_type_ref()?;
        self.consume(&TokenKind::Be, "变量名之后须有“为”")?;
        let value = self.expression()?;
        self.end_statement()?;
        Ok(self.stmt(
            start,
            StmtKind::Let {
                name,
                type_ref,
                value,
                mutable,
            },
        ))
    }

    fn function_statement(&mut self, start: Span, is_async: bool) -> Result<Stmt, ParseError> {
        let (name, _) = self.identifier_token("“法”之后须有函数名")?;
        self.consume(&TokenKind::LeftParen, "函数名之后须有左括号")?;
        let mut params = Vec::new();
        if !self.check(&TokenKind::RightParen) {
            loop {
                if params.len() >= 255 {
                    return Err(self.error_here("函数至多可收 255 个参数"));
                }
                let (param_name, param_span) = self.identifier_token("此处须有参数名")?;
                let type_ref = self.optional_type_ref()?;
                let span = type_ref.as_ref().map_or_else(
                    || param_span.clone(),
                    |type_ref| param_span.through(&type_ref.span),
                );
                params.push(Parameter {
                    name: param_name,
                    type_ref,
                    span,
                });
                if !self.matches(&TokenKind::Comma) {
                    break;
                }
                if self.check(&TokenKind::RightParen) {
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
        Ok(self.stmt(
            start,
            StmtKind::Function {
                name,
                params,
                return_type,
                body,
                is_async,
            },
        ))
    }

    fn class_statement(&mut self, start: Span) -> Result<Stmt, ParseError> {
        let (name, _) = self.identifier_token("“类”之后须有类名")?;
        let superclass = if self.matches(&TokenKind::Inherit) {
            Some(self.identifier_token("“承”之后须有父类名")?.0)
        } else {
            None
        };
        let mut protocols = Vec::new();
        if self.matches(&TokenKind::Implements) {
            loop {
                protocols.push(self.identifier_token("“纳”之后须有协名")?.0);
                if !self.matches(&TokenKind::Comma) {
                    break;
                }
            }
        }
        self.consume(&TokenKind::Then, "类正文之前须有“则”")?;
        let mut fields = Vec::new();
        let mut methods = Vec::new();
        while !self.check(&TokenKind::End) && !self.check(&TokenKind::Eof) {
            let visibility = if self.matches(&TokenKind::Public) {
                Visibility::Public
            } else if self.matches(&TokenKind::Private) {
                Visibility::Private
            } else {
                Visibility::Public
            };
            let mut readonly = false;
            let mut is_static = false;
            loop {
                if self.matches(&TokenKind::Readonly) {
                    readonly = true;
                } else if self.matches(&TokenKind::Static) {
                    is_static = true;
                } else {
                    break;
                }
            }
            let is_async = self.matches(&TokenKind::Async);
            if self.matches(&TokenKind::Field) {
                if is_async {
                    return Err(self.error_previous("“异”只可修饰法"));
                }
                fields.push(self.field_declaration(
                    self.previous().span.clone(),
                    visibility,
                    readonly,
                    is_static,
                )?);
            } else if self.matches(&TokenKind::Function) {
                if readonly {
                    return Err(self.error_previous("“只”只能修饰域"));
                }
                let mut method = self.function_statement(self.previous().span.clone(), is_async)?;
                method.member_visibility = visibility;
                method.is_static = is_static;
                methods.push(method);
            } else {
                return Err(self.error_here("类正文中须声明“域”或“法”"));
            }
        }
        self.consume(&TokenKind::End, "类末尾须有“终”")?;
        self.matches(&TokenKind::Semicolon);
        Ok(self.stmt(
            start,
            StmtKind::Class {
                name,
                superclass,
                protocols,
                fields,
                methods,
            },
        ))
    }

    fn protocol_statement(&mut self, start: Span) -> Result<Stmt, ParseError> {
        let (name, _) = self.identifier_token("“协”之后须有协名")?;
        self.consume(&TokenKind::Then, "协正文之前须有“则”")?;
        let mut fields = Vec::new();
        let mut methods = Vec::new();
        while !self.check(&TokenKind::End) && !self.check(&TokenKind::Eof) {
            let is_async = self.matches(&TokenKind::Async);
            if self.matches(&TokenKind::Field) {
                if is_async {
                    return Err(self.error_previous("“异”只可修饰法签名"));
                }
                fields.push(self.field_declaration(
                    self.previous().span.clone(),
                    Visibility::Public,
                    false,
                    false,
                )?);
            } else if self.matches(&TokenKind::Function) {
                methods.push(self.protocol_method(self.previous().span.clone(), is_async)?);
            } else {
                return Err(self.error_here("协正文中须有“域”或法签名"));
            }
        }
        self.consume(&TokenKind::End, "协末尾须有“终”")?;
        self.matches(&TokenKind::Semicolon);
        Ok(self.stmt(
            start,
            StmtKind::Protocol {
                name,
                fields,
                methods,
            },
        ))
    }

    fn field_declaration(
        &mut self,
        start: Span,
        visibility: Visibility,
        readonly: bool,
        is_static: bool,
    ) -> Result<FieldDecl, ParseError> {
        let (name, _) = self.identifier_token("“域”之后须有字段名")?;
        let type_ref = self
            .optional_type_ref()?
            .ok_or_else(|| self.error_here("域必须注明类型"))?;
        let initial = if self.matches(&TokenKind::Be) {
            Some(self.expression()?)
        } else {
            None
        };
        self.end_statement()?;
        Ok(FieldDecl {
            name,
            type_ref,
            initial,
            visibility,
            readonly,
            is_static,
            span: start.through(&self.previous().span),
        })
    }

    fn protocol_method(&mut self, start: Span, is_async: bool) -> Result<Stmt, ParseError> {
        let (name, _) = self.identifier_token("“法”之后须有签名名")?;
        self.consume(&TokenKind::LeftParen, "法签名名之后须有左括号")?;
        let mut params = Vec::new();
        if !self.check(&TokenKind::RightParen) {
            loop {
                let (param_name, param_span) = self.identifier_token("此处须有参数名")?;
                let type_ref = self.optional_type_ref()?;
                let span = type_ref.as_ref().map_or_else(
                    || param_span.clone(),
                    |type_ref| param_span.through(&type_ref.span),
                );
                params.push(Parameter {
                    name: param_name,
                    type_ref,
                    span,
                });
                if !self.matches(&TokenKind::Comma) {
                    break;
                }
            }
        }
        self.consume(&TokenKind::RightParen, "法签名参数之后须有右括号")?;
        let return_type = self.optional_type_ref()?;
        self.end_statement()?;
        Ok(self.stmt(
            start,
            StmtKind::Function {
                name,
                params,
                return_type,
                body: Vec::new(),
                is_async,
            },
        ))
    }

    fn import_statement(&mut self, start: Span) -> Result<Stmt, ParseError> {
        let path = match self.advance().kind.clone() {
            TokenKind::String(path) => path,
            _ => return Err(self.error_previous("“引”之后须有文字路径")),
        };
        if !self.matches(&TokenKind::Be) && !self.matches(&TokenKind::As) {
            return Err(self.error_here("模块路径之后须有“为”或“作”"));
        }
        let (alias, _) = self.identifier_token("“为”之后须有模块名")?;
        self.end_statement()?;
        Ok(self.stmt(start, StmtKind::Import { path, alias }))
    }

    fn statement(&mut self) -> Result<Stmt, ParseError> {
        if self.matches(&TokenKind::Set) {
            return self.set_statement(self.previous().span.clone());
        }
        if self.matches(&TokenKind::Print) {
            return self.print_statement(self.previous().span.clone());
        }
        if self.matches(&TokenKind::If) {
            return self.if_statement(self.previous().span.clone());
        }
        if self.matches(&TokenKind::While) {
            return self.while_statement(self.previous().span.clone());
        }
        if self.matches(&TokenKind::For) {
            return self.for_statement(self.previous().span.clone());
        }
        if self.matches(&TokenKind::Try) {
            return self.try_statement(self.previous().span.clone());
        }
        if self.matches(&TokenKind::Throw) {
            return self.throw_statement(self.previous().span.clone());
        }
        if self.matches(&TokenKind::Return) {
            return self.return_statement(self.previous().span.clone());
        }
        let start = self.peek().span.clone();
        let expression = self.expression()?;
        self.end_statement()?;
        Ok(self.stmt(start, StmtKind::Expression(expression)))
    }

    fn set_statement(&mut self, start: Span) -> Result<Stmt, ParseError> {
        let target = self.call()?;
        if !matches!(
            target.kind,
            ExprKind::Variable(_) | ExprKind::Get { .. } | ExprKind::Index { .. }
        ) {
            return Err(self.error_previous("“置”只能改写变量、字段或下标"));
        }
        self.consume(&TokenKind::Be, "改写目标之后须有“为”")?;
        let value = self.expression()?;
        self.end_statement()?;
        Ok(self.stmt(start, StmtKind::Set { target, value }))
    }

    fn print_statement(&mut self, start: Span) -> Result<Stmt, ParseError> {
        let value = self.expression()?;
        self.end_statement()?;
        Ok(self.stmt(start, StmtKind::Print(value)))
    }

    fn if_statement(&mut self, start: Span) -> Result<Stmt, ParseError> {
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
        Ok(self.stmt(
            start,
            StmtKind::If {
                condition,
                then_branch,
                else_branch,
            },
        ))
    }

    fn while_statement(&mut self, start: Span) -> Result<Stmt, ParseError> {
        let condition = self.expression()?;
        self.consume(&TokenKind::Then, "循环条件之后须有“则”")?;
        let body = self.block_until(&[TokenKind::End])?;
        self.consume(&TokenKind::End, "循环末尾须有“终”")?;
        self.matches(&TokenKind::Semicolon);
        Ok(self.stmt(start, StmtKind::While { condition, body }))
    }

    fn for_statement(&mut self, start: Span) -> Result<Stmt, ParseError> {
        let (name, _) = self.identifier_token("“逐”之后须有迭代变量名")?;
        let type_ref = self.optional_type_ref()?;
        self.consume(&TokenKind::In, "迭代变量之后须有“于”")?;
        let iterable = self.expression()?;
        self.consume(&TokenKind::Then, "迭代对象之后须有“则”")?;
        let body = self.block_until(&[TokenKind::End])?;
        self.consume(&TokenKind::End, "逐循环末尾须有“终”")?;
        self.matches(&TokenKind::Semicolon);
        Ok(self.stmt(
            start,
            StmtKind::For {
                name,
                type_ref,
                iterable,
                body,
            },
        ))
    }

    fn try_statement(&mut self, start: Span) -> Result<Stmt, ParseError> {
        self.consume(&TokenKind::Then, "“试”之后须有“则”")?;
        let try_branch = self.block_until(&[TokenKind::Catch])?;
        self.consume(&TokenKind::Catch, "“试”必须有“救”分支")?;
        let (error_name, _) = self.identifier_token("“救”之后须有错误变量名")?;
        self.consume(&TokenKind::Then, "错误变量之后须有“则”")?;
        let catch_branch = self.block_until(&[TokenKind::End])?;
        self.consume(&TokenKind::End, "“试”语句末尾须有“终”")?;
        self.matches(&TokenKind::Semicolon);
        Ok(self.stmt(
            start,
            StmtKind::Try {
                try_branch,
                error_name,
                catch_branch,
            },
        ))
    }

    fn throw_statement(&mut self, start: Span) -> Result<Stmt, ParseError> {
        let value = self.expression()?;
        self.end_statement()?;
        Ok(self.stmt(start, StmtKind::Throw(value)))
    }

    fn return_statement(&mut self, start: Span) -> Result<Stmt, ParseError> {
        let value = if self.check(&TokenKind::Semicolon) {
            None
        } else {
            Some(self.expression()?)
        };
        self.end_statement()?;
        Ok(self.stmt(start, StmtKind::Return(value)))
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
            let span = expr.span.through(&right.span);
            expr = Expr::new(
                ExprKind::Binary {
                    left: Box::new(expr),
                    operator,
                    right: Box::new(right),
                },
                span,
            );
        }
        Ok(expr)
    }

    fn and(&mut self) -> Result<Expr, ParseError> {
        let mut expr = self.equality()?;
        while self.matches(&TokenKind::And) {
            let operator = self.previous().kind.clone();
            let right = self.equality()?;
            let span = expr.span.through(&right.span);
            expr = Expr::new(
                ExprKind::Binary {
                    left: Box::new(expr),
                    operator,
                    right: Box::new(right),
                },
                span,
            );
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
            let span = expr.span.through(&right.span);
            expr = Expr::new(
                ExprKind::Binary {
                    left: Box::new(expr),
                    operator,
                    right: Box::new(right),
                },
                span,
            );
        }
        Ok(expr)
    }

    fn unary(&mut self) -> Result<Expr, ParseError> {
        if self.matches(&TokenKind::Await) {
            let start = self.previous().span.clone();
            let task = self.unary()?;
            let span = start.through(&task.span);
            return Ok(Expr::new(
                ExprKind::Await {
                    task: Box::new(task),
                },
                span,
            ));
        }
        if self.matches(&TokenKind::Bang)
            || self.matches(&TokenKind::Not)
            || self.matches(&TokenKind::Minus)
        {
            let operator_token = self.previous().clone();
            let right = self.unary()?;
            let span = operator_token.span.through(&right.span);
            return Ok(Expr::new(
                ExprKind::Unary {
                    operator: operator_token.kind,
                    right: Box::new(right),
                },
                span,
            ));
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
                        if self.check(&TokenKind::RightParen) {
                            break;
                        }
                    }
                }
                let close = self
                    .consume(&TokenKind::RightParen, "实参之后须有右括号")?
                    .span
                    .clone();
                let span = expr.span.through(&close);
                expr = Expr::new(
                    ExprKind::Call {
                        callee: Box::new(expr),
                        arguments,
                    },
                    span,
                );
            } else if self.matches(&TokenKind::Dot) {
                let (name, name_span) = self.identifier_token("点号之后须有成员名")?;
                let span = expr.span.through(&name_span);
                expr = Expr::new(
                    ExprKind::Get {
                        object: Box::new(expr),
                        name,
                    },
                    span,
                );
            } else if self.matches(&TokenKind::LeftBracket) {
                expr = self.index_or_slice(expr)?;
            } else {
                break;
            }
        }
        Ok(expr)
    }

    fn index_or_slice(&mut self, object: Expr) -> Result<Expr, ParseError> {
        if self.matches(&TokenKind::Colon) {
            let end = if self.check(&TokenKind::RightBracket) {
                None
            } else {
                Some(Box::new(self.expression()?))
            };
            let close = self
                .consume(&TokenKind::RightBracket, "切片末尾须有右方括号")?
                .span
                .clone();
            let span = object.span.through(&close);
            return Ok(Expr::new(
                ExprKind::Slice {
                    object: Box::new(object),
                    start: None,
                    end,
                },
                span,
            ));
        }

        let first = self.expression()?;
        if self.matches(&TokenKind::Colon) {
            let end = if self.check(&TokenKind::RightBracket) {
                None
            } else {
                Some(Box::new(self.expression()?))
            };
            let close = self
                .consume(&TokenKind::RightBracket, "切片末尾须有右方括号")?
                .span
                .clone();
            let span = object.span.through(&close);
            Ok(Expr::new(
                ExprKind::Slice {
                    object: Box::new(object),
                    start: Some(Box::new(first)),
                    end,
                },
                span,
            ))
        } else {
            let close = self
                .consume(&TokenKind::RightBracket, "下标之后须有右方括号")?
                .span
                .clone();
            let span = object.span.through(&close);
            Ok(Expr::new(
                ExprKind::Index {
                    object: Box::new(object),
                    index: Box::new(first),
                },
                span,
            ))
        }
    }

    fn primary(&mut self) -> Result<Expr, ParseError> {
        if self.check(&TokenKind::Eof) {
            return Err(self.error_here("此处应有数值、文字、变量或括号表达式"));
        }
        let token = self.advance().clone();
        let span = token.span.clone();
        match token.kind {
            TokenKind::False => Ok(Expr::new(ExprKind::Literal(Literal::Bool(false)), span)),
            TokenKind::True => Ok(Expr::new(ExprKind::Literal(Literal::Bool(true)), span)),
            TokenKind::Nil => Ok(Expr::new(ExprKind::Literal(Literal::Nil), span)),
            TokenKind::Number(value) => {
                Ok(Expr::new(ExprKind::Literal(Literal::Number(value)), span))
            }
            TokenKind::String(value) => {
                Ok(Expr::new(ExprKind::Literal(Literal::String(value)), span))
            }
            TokenKind::Identifier(name) => Ok(Expr::new(ExprKind::Variable(name), span)),
            TokenKind::This => Ok(Expr::new(ExprKind::This, span)),
            TokenKind::LeftBracket => self.list_literal(span),
            TokenKind::LeftBrace => self.map_literal(span),
            TokenKind::LeftParen => self.group_or_tuple(span),
            _ => Err(ParseError {
                message: "此处应有数值、文字、变量或括号表达式".into(),
                line: span.line,
                column: span.column,
                span,
            }),
        }
    }

    fn group_or_tuple(&mut self, open: Span) -> Result<Expr, ParseError> {
        if self.check(&TokenKind::RightParen) {
            return Err(self.error_here("空元组请写为“元组（）”尚未支持；元组至少须有一项"));
        }
        let first = self.expression()?;
        if !self.matches(&TokenKind::Comma) {
            self.consume(&TokenKind::RightParen, "表达式之后须有右括号")?;
            return Ok(first);
        }

        let mut items = vec![first];
        while !self.check(&TokenKind::RightParen) {
            items.push(self.expression()?);
            if !self.matches(&TokenKind::Comma) {
                break;
            }
        }
        let close = self
            .consume(&TokenKind::RightParen, "元组末尾须有右括号")?
            .span
            .clone();
        Ok(Expr::new(ExprKind::Tuple(items), open.through(&close)))
    }

    fn list_literal(&mut self, open: Span) -> Result<Expr, ParseError> {
        let mut items = Vec::new();
        if !self.check(&TokenKind::RightBracket) {
            loop {
                items.push(self.expression()?);
                if !self.matches(&TokenKind::Comma) {
                    break;
                }
                if self.check(&TokenKind::RightBracket) {
                    break;
                }
            }
        }
        let close = self
            .consume(&TokenKind::RightBracket, "列末尾须有右方括号")?
            .span
            .clone();
        Ok(Expr::new(ExprKind::List(items), open.through(&close)))
    }

    fn map_literal(&mut self, open: Span) -> Result<Expr, ParseError> {
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
                if self.check(&TokenKind::RightBrace) {
                    break;
                }
            }
        }
        let close = self
            .consume(&TokenKind::RightBrace, "典末尾须有右花括号")?
            .span
            .clone();
        Ok(Expr::new(ExprKind::Map(entries), open.through(&close)))
    }

    fn optional_type_ref(&mut self) -> Result<Option<TypeRef>, ParseError> {
        if !self.matches(&TokenKind::Colon) {
            return Ok(None);
        }
        let colon = self.previous().span.clone();
        let (kind, span) = self.type_union()?;
        Ok(Some(TypeRef::new(kind, colon.through(&span))))
    }

    fn type_union(&mut self) -> Result<(TypeKind, Span), ParseError> {
        let (first, mut span) = self.type_primary()?;
        let mut variants = vec![first];
        while self.matches(&TokenKind::Pipe) {
            let (variant, variant_span) = self.type_primary().map_err(|mut error| {
                error.message = "联合类型的“|”之后须有完整类型".into();
                error
            })?;
            span = span.through(&variant_span);
            variants.push(variant);
        }
        if variants.len() == 1 {
            Ok((variants.pop().expect("one type variant"), span))
        } else {
            Ok((TypeKind::Union(variants), span))
        }
    }

    fn type_primary(&mut self) -> Result<(TypeKind, Span), ParseError> {
        let token = self.advance().clone();
        let (mut kind, mut span) = match token.kind {
            TokenKind::Identifier(name) => {
                if self.matches(&TokenKind::Less) {
                    let mut arguments = Vec::new();
                    loop {
                        arguments.push(self.type_union()?.0);
                        if !self.matches(&TokenKind::Comma) {
                            break;
                        }
                    }
                    let close = self
                        .consume(&TokenKind::Greater, "泛型类型末尾须有“>”")?
                        .span
                        .clone();
                    (
                        TypeKind::Generic {
                            base: name,
                            arguments,
                        },
                        token.span.through(&close),
                    )
                } else {
                    (TypeKind::Named(name), token.span)
                }
            }
            TokenKind::Nil => (TypeKind::Named("空".into()), token.span),
            TokenKind::Class => (TypeKind::Named("类".into()), token.span),
            TokenKind::Function if self.matches(&TokenKind::LeftParen) => {
                let mut parameters = Vec::new();
                if !self.check(&TokenKind::RightParen) {
                    loop {
                        parameters.push(self.type_union()?.0);
                        if !self.matches(&TokenKind::Comma) {
                            break;
                        }
                    }
                }
                self.consume(&TokenKind::RightParen, "法类型参数末尾须有右括号")?;
                self.consume(&TokenKind::Colon, "法类型须以“：”注明归值")?;
                let (result, result_span) = self.type_union()?;
                (
                    TypeKind::Function {
                        parameters,
                        result: Box::new(result),
                    },
                    token.span.through(&result_span),
                )
            }
            TokenKind::Function => (TypeKind::Named("法".into()), token.span),
            _ => {
                return Err(ParseError {
                    message: "此处须有类型名、泛型类型或法类型".into(),
                    line: token.line,
                    column: token.column,
                    span: token.span,
                });
            }
        };
        if self.matches(&TokenKind::Question) {
            span = span.through(&self.previous().span);
            kind = TypeKind::Nullable(Box::new(kind));
        }
        Ok((kind, span))
    }

    fn end_statement(&mut self) -> Result<(), ParseError> {
        self.consume(&TokenKind::Semicolon, "语句末尾须有“；”")?;
        Ok(())
    }

    fn identifier_token(&mut self, message: &str) -> Result<(String, Span), ParseError> {
        let token = self.advance().clone();
        match token.kind {
            TokenKind::Identifier(name) => Ok((name, token.span)),
            _ => Err(ParseError {
                message: message.into(),
                line: token.line,
                column: token.column,
                span: token.span,
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

    fn stmt(&self, start: Span, kind: StmtKind) -> Stmt {
        Stmt::new(kind, start.through(&self.previous().span))
    }

    fn error_here(&self, message: impl Into<String>) -> ParseError {
        ParseError {
            message: message.into(),
            line: self.peek().line,
            column: self.peek().column,
            span: self.peek().span.clone(),
        }
    }

    fn error_previous(&self, message: impl Into<String>) -> ParseError {
        ParseError {
            message: message.into(),
            line: self.previous().line,
            column: self.previous().column,
            span: self.previous().span.clone(),
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
            matches!(&statements[0].kind, StmtKind::Function { name, params, .. } if name == "相加" && params.len() == 2)
        );
    }

    #[test]
    fn parses_async_functions_and_await_expressions() {
        let statements = crate::parse(
            "异 法 加一（值：数）：数 则 归 值 加 1；终 定 所得：数 为 候 加一（1）；",
        )
        .unwrap();
        assert!(matches!(
            &statements[0].kind,
            StmtKind::Function { is_async: true, .. }
        ));
        let StmtKind::Let { value, .. } = &statements[1].kind else {
            panic!("expected binding")
        };
        assert!(matches!(value.kind, ExprKind::Await { .. }));
    }

    #[test]
    fn parses_structured_generic_nullable_and_function_types() {
        let source = "法 应用（操作：法（数）：数，值：数?）：列<数|文> 则 归【操作（1）】；终";
        let statements = parse(lexer::scan(source).unwrap()).unwrap();
        let StmtKind::Function {
            params,
            return_type,
            ..
        } = &statements[0].kind
        else {
            panic!("expected function")
        };
        assert!(matches!(
            params[0].type_ref.as_ref().map(|ty| &ty.kind),
            Some(TypeKind::Function { .. })
        ));
        assert_eq!(params[1].type_ref.as_ref().unwrap().name, "数?");
        assert_eq!(return_type.as_ref().unwrap().name, "列<数|文>");
    }

    #[test]
    fn parses_class_members() {
        let tokens =
            lexer::scan("类 人 则 法 初始化（姓名：文）则 置 此.姓名 为 姓名；终 终").unwrap();
        let statements = parse(tokens).unwrap();
        assert!(
            matches!(&statements[0].kind, StmtKind::Class { name, methods, .. } if name == "人" && methods.len() == 1)
        );
    }

    #[test]
    fn parses_protocol_fields_visibility_and_static_methods() {
        let source = r#"
            协 可命名 则 域 姓名：文；法 显示（）：文；终
            类 用户 纳 可命名 则
                公 只 域 姓名：文；
                私 域 密语：文 为「无」；
                公 静 法 新建（姓名：文）：用户 则 归 用户（姓名）；终
                公 法 显示（）：文 则 归 此.姓名；终
            终
        "#;
        let statements = parse(lexer::scan(source).unwrap()).unwrap();
        assert!(
            matches!(&statements[0].kind, StmtKind::Protocol { fields, methods, .. } if fields.len() == 1 && methods.len() == 1)
        );
        assert!(
            matches!(&statements[1].kind, StmtKind::Class { protocols, fields, methods, .. } if protocols == &["可命名"] && fields.len() == 2 && methods[0].is_static)
        );
    }

    #[test]
    fn parses_tuple_slice_and_try() {
        let source = "定 项目：元 为（1，2，3）；言 项目【1：】；试 则 言 项目；救 错 则 抛 错；终";
        let statements = parse(lexer::scan(source).unwrap()).unwrap();
        assert_eq!(statements.len(), 3);
        assert!(matches!(
            &statements[1].kind,
            StmtKind::Print(Expr {
                kind: ExprKind::Slice { .. },
                ..
            })
        ));
    }

    #[test]
    fn parse_errors_render_source_excerpt() {
        let error = parse(lexer::scan_named("言 1\n", "坏例.yx").unwrap()).unwrap_err();
        let rendered = error.to_string();
        assert!(rendered.contains("坏例.yx:2:1"));
        assert!(rendered.contains("语句末尾须有"));
    }
}
