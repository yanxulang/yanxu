use crate::ast::{
    Expr, ExprKind, FieldDecl, Literal, Parameter, Stmt, StmtKind, TypeKind, TypePath,
    TypePathSegment, TypeRef, Visibility,
};
use crate::source::Span;
use crate::token::{Token, TokenKind};
use std::fmt;

const MAX_SYNTAX_DEPTH: usize = 32;
const SYNTAX_DEPTH_ERROR: &str = "语法结构深度不得超过 32 层";

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
    Parser {
        tokens,
        current: 0,
        scope_depth: 0,
        statement_depth: 0,
        expression_depth: 0,
        type_depth: 0,
    }
    .program()
}

struct ParsedExpr {
    expr: Expr,
    depth: usize,
}

struct Parser {
    tokens: Vec<Token>,
    current: usize,
    scope_depth: usize,
    statement_depth: usize,
    expression_depth: usize,
    type_depth: usize,
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
        self.with_statement_depth(Self::declaration_inner)
    }

    fn declaration_inner(&mut self) -> Result<Stmt, ParseError> {
        if self.matches(&TokenKind::Public) {
            let public_span = self.previous().span.clone();
            let mut statement = self.declaration()?;
            if !matches!(
                statement.kind,
                StmtKind::Let { .. }
                    | StmtKind::Function { .. }
                    | StmtKind::Class { .. }
                    | StmtKind::Protocol { .. }
                    | StmtKind::Import { .. }
            ) {
                return Err(ParseError {
                    message: "“公”只可修饰变量、常量、法、类、协或顶层引入".into(),
                    line: public_span.line,
                    column: public_span.column,
                    span: public_span,
                });
            }
            if matches!(statement.kind, StmtKind::Import { .. }) && self.scope_depth > 0 {
                return Err(ParseError {
                    message: "“公 引”只可用于模块顶层".into(),
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
            Some(self.type_path("“承”之后须有父类路径")?)
        } else {
            None
        };
        let mut protocols = Vec::new();
        if self.matches(&TokenKind::Implements) {
            loop {
                protocols.push(self.type_path("“纳”之后须有协路径")?);
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
        let target = self.with_expression_depth(Self::call)?.expr;
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
        self.scope_depth += 1;
        let result = (|| {
            let mut statements = Vec::new();
            while !self.check(&TokenKind::Eof) && !endings.iter().any(|kind| self.check(kind)) {
                statements.push(self.declaration()?);
            }
            Ok(statements)
        })();
        self.scope_depth -= 1;
        result
    }

    fn expression(&mut self) -> Result<Expr, ParseError> {
        Ok(self.parsed_expression()?.expr)
    }

    fn parsed_expression(&mut self) -> Result<ParsedExpr, ParseError> {
        self.with_expression_depth(Self::or)
    }

    fn or(&mut self) -> Result<ParsedExpr, ParseError> {
        let mut expr = self.and()?;
        while self.matches(&TokenKind::Or) {
            let operator = self.previous().kind.clone();
            let right = self.and()?;
            let span = expr.expr.span.through(&right.expr.span);
            let depth = expr.depth.max(right.depth).saturating_add(1);
            expr = self.parsed_expr(
                ExprKind::Binary {
                    left: Box::new(expr.expr),
                    operator,
                    right: Box::new(right.expr),
                },
                span,
                depth,
            )?;
        }
        Ok(expr)
    }

    fn and(&mut self) -> Result<ParsedExpr, ParseError> {
        let mut expr = self.equality()?;
        while self.matches(&TokenKind::And) {
            let operator = self.previous().kind.clone();
            let right = self.equality()?;
            let span = expr.expr.span.through(&right.expr.span);
            let depth = expr.depth.max(right.depth).saturating_add(1);
            expr = self.parsed_expr(
                ExprKind::Binary {
                    left: Box::new(expr.expr),
                    operator,
                    right: Box::new(right.expr),
                },
                span,
                depth,
            )?;
        }
        Ok(expr)
    }

    fn equality(&mut self) -> Result<ParsedExpr, ParseError> {
        self.binary(
            Self::type_test,
            &[TokenKind::EqualEqual, TokenKind::BangEqual],
        )
    }

    fn type_test(&mut self) -> Result<ParsedExpr, ParseError> {
        let mut expr = self.comparison()?;
        while self.matches(&TokenKind::Is) {
            let (kind, type_span) = self.type_union().map_err(|mut error| {
                error.message = "“是”之后须有完整类型".into();
                error
            })?;
            let span = expr.expr.span.through(&type_span);
            let depth = expr.depth.saturating_add(1);
            expr = self.parsed_expr(
                ExprKind::TypeTest {
                    value: Box::new(expr.expr),
                    type_ref: TypeRef::new(kind, type_span),
                },
                span,
                depth,
            )?;
        }
        Ok(expr)
    }

    fn comparison(&mut self) -> Result<ParsedExpr, ParseError> {
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

    fn term(&mut self) -> Result<ParsedExpr, ParseError> {
        self.binary(Self::factor, &[TokenKind::Plus, TokenKind::Minus])
    }

    fn factor(&mut self) -> Result<ParsedExpr, ParseError> {
        self.binary(Self::unary, &[TokenKind::Star, TokenKind::Slash])
    }

    fn binary(
        &mut self,
        next: fn(&mut Self) -> Result<ParsedExpr, ParseError>,
        operators: &[TokenKind],
    ) -> Result<ParsedExpr, ParseError> {
        let mut expr = next(self)?;
        while operators.iter().any(|kind| self.check(kind)) {
            let operator = self.advance().kind.clone();
            let right = next(self)?;
            let span = expr.expr.span.through(&right.expr.span);
            let depth = expr.depth.max(right.depth).saturating_add(1);
            expr = self.parsed_expr(
                ExprKind::Binary {
                    left: Box::new(expr.expr),
                    operator,
                    right: Box::new(right.expr),
                },
                span,
                depth,
            )?;
        }
        Ok(expr)
    }

    fn unary(&mut self) -> Result<ParsedExpr, ParseError> {
        if self.matches(&TokenKind::Await) {
            let start = self.previous().span.clone();
            let task = self.with_expression_depth(Self::unary)?;
            let span = start.through(&task.expr.span);
            let depth = task.depth.saturating_add(1);
            return self.parsed_expr(
                ExprKind::Await {
                    task: Box::new(task.expr),
                },
                span,
                depth,
            );
        }
        if self.matches(&TokenKind::Bang)
            || self.matches(&TokenKind::Not)
            || self.matches(&TokenKind::Minus)
        {
            let operator_token = self.previous().clone();
            let right = self.with_expression_depth(Self::unary)?;
            let span = operator_token.span.through(&right.expr.span);
            let depth = right.depth.saturating_add(1);
            return self.parsed_expr(
                ExprKind::Unary {
                    operator: operator_token.kind,
                    right: Box::new(right.expr),
                },
                span,
                depth,
            );
        }
        self.call()
    }

    fn call(&mut self) -> Result<ParsedExpr, ParseError> {
        let mut expr = self.primary()?;
        loop {
            if self.matches(&TokenKind::LeftParen) {
                let mut arguments = Vec::new();
                if !self.check(&TokenKind::RightParen) {
                    loop {
                        if arguments.len() >= 255 {
                            return Err(self.error_here("一次调用至多可传 255 个参数"));
                        }
                        arguments.push(self.parsed_expression()?);
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
                let span = expr.expr.span.through(&close);
                let depth = arguments
                    .iter()
                    .map(|argument| argument.depth)
                    .max()
                    .unwrap_or(0)
                    .max(expr.depth)
                    .saturating_add(1);
                expr = self.parsed_expr(
                    ExprKind::Call {
                        callee: Box::new(expr.expr),
                        arguments: arguments
                            .into_iter()
                            .map(|argument| argument.expr)
                            .collect(),
                    },
                    span,
                    depth,
                )?;
            } else if self.matches(&TokenKind::Dot) {
                let (name, name_span) = self.identifier_token("点号之后须有成员名")?;
                let span = expr.expr.span.through(&name_span);
                let depth = expr.depth.saturating_add(1);
                expr = self.parsed_expr(
                    ExprKind::Get {
                        object: Box::new(expr.expr),
                        name,
                    },
                    span,
                    depth,
                )?;
            } else if self.matches(&TokenKind::LeftBracket) {
                expr = self.index_or_slice(expr)?;
            } else {
                break;
            }
        }
        Ok(expr)
    }

    fn index_or_slice(&mut self, object: ParsedExpr) -> Result<ParsedExpr, ParseError> {
        if self.matches(&TokenKind::Colon) {
            let end = if self.check(&TokenKind::RightBracket) {
                None
            } else {
                Some(self.parsed_expression()?)
            };
            let close = self
                .consume(&TokenKind::RightBracket, "切片末尾须有右方括号")?
                .span
                .clone();
            let span = object.expr.span.through(&close);
            let depth = end
                .as_ref()
                .map_or(object.depth, |end| object.depth.max(end.depth))
                .saturating_add(1);
            return self.parsed_expr(
                ExprKind::Slice {
                    object: Box::new(object.expr),
                    start: None,
                    end: end.map(|end| Box::new(end.expr)),
                },
                span,
                depth,
            );
        }

        let first = self.parsed_expression()?;
        if self.matches(&TokenKind::Colon) {
            let end = if self.check(&TokenKind::RightBracket) {
                None
            } else {
                Some(self.parsed_expression()?)
            };
            let close = self
                .consume(&TokenKind::RightBracket, "切片末尾须有右方括号")?
                .span
                .clone();
            let span = object.expr.span.through(&close);
            let depth = object
                .depth
                .max(first.depth)
                .max(end.as_ref().map_or(0, |end| end.depth))
                .saturating_add(1);
            self.parsed_expr(
                ExprKind::Slice {
                    object: Box::new(object.expr),
                    start: Some(Box::new(first.expr)),
                    end: end.map(|end| Box::new(end.expr)),
                },
                span,
                depth,
            )
        } else {
            let close = self
                .consume(&TokenKind::RightBracket, "下标之后须有右方括号")?
                .span
                .clone();
            let span = object.expr.span.through(&close);
            let depth = object.depth.max(first.depth).saturating_add(1);
            self.parsed_expr(
                ExprKind::Index {
                    object: Box::new(object.expr),
                    index: Box::new(first.expr),
                },
                span,
                depth,
            )
        }
    }

    fn primary(&mut self) -> Result<ParsedExpr, ParseError> {
        if self.check(&TokenKind::Eof) {
            return Err(self.error_here("此处应有数值、文字、变量或括号表达式"));
        }
        let token = self.advance().clone();
        let span = token.span.clone();
        match token.kind {
            TokenKind::False => self.parsed_expr(ExprKind::Literal(Literal::Bool(false)), span, 1),
            TokenKind::True => self.parsed_expr(ExprKind::Literal(Literal::Bool(true)), span, 1),
            TokenKind::Nil => self.parsed_expr(ExprKind::Literal(Literal::Nil), span, 1),
            TokenKind::Number(value) => {
                self.parsed_expr(ExprKind::Literal(Literal::Number(value)), span, 1)
            }
            TokenKind::String(value) => {
                self.parsed_expr(ExprKind::Literal(Literal::String(value)), span, 1)
            }
            TokenKind::Identifier(name) => self.parsed_expr(ExprKind::Variable(name), span, 1),
            TokenKind::This => self.parsed_expr(ExprKind::This, span, 1),
            TokenKind::Super => {
                self.consume(&TokenKind::Dot, "“父”之后须以点号指定父类方法")?;
                let (method, method_span) = self.identifier_token("“父.”之后须有父类方法名")?;
                self.parsed_expr(ExprKind::Super { method }, span.through(&method_span), 1)
            }
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

    fn group_or_tuple(&mut self, open: Span) -> Result<ParsedExpr, ParseError> {
        if self.check(&TokenKind::RightParen) {
            return Err(self.error_here("空元组请写为“元组（）”尚未支持；元组至少须有一项"));
        }
        let first = self.parsed_expression()?;
        if !self.matches(&TokenKind::Comma) {
            self.consume(&TokenKind::RightParen, "表达式之后须有右括号")?;
            return Ok(first);
        }

        let mut items = vec![first];
        while !self.check(&TokenKind::RightParen) {
            items.push(self.parsed_expression()?);
            if !self.matches(&TokenKind::Comma) {
                break;
            }
        }
        let close = self
            .consume(&TokenKind::RightParen, "元组末尾须有右括号")?
            .span
            .clone();
        let depth = items
            .iter()
            .map(|item| item.depth)
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        self.parsed_expr(
            ExprKind::Tuple(items.into_iter().map(|item| item.expr).collect()),
            open.through(&close),
            depth,
        )
    }

    fn list_literal(&mut self, open: Span) -> Result<ParsedExpr, ParseError> {
        let mut items = Vec::new();
        if !self.check(&TokenKind::RightBracket) {
            loop {
                items.push(self.parsed_expression()?);
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
        let depth = items
            .iter()
            .map(|item| item.depth)
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        self.parsed_expr(
            ExprKind::List(items.into_iter().map(|item| item.expr).collect()),
            open.through(&close),
            depth,
        )
    }

    fn map_literal(&mut self, open: Span) -> Result<ParsedExpr, ParseError> {
        let mut entries = Vec::new();
        if !self.check(&TokenKind::RightBrace) {
            loop {
                let key = self.parsed_expression()?;
                self.consume(&TokenKind::Colon, "典之键后须有冒号")?;
                let value = self.parsed_expression()?;
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
        let depth = entries
            .iter()
            .flat_map(|(key, value)| [key.depth, value.depth])
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        self.parsed_expr(
            ExprKind::Map(
                entries
                    .into_iter()
                    .map(|(key, value)| (key.expr, value.expr))
                    .collect(),
            ),
            open.through(&close),
            depth,
        )
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
        self.with_type_depth(Self::type_union_inner)
    }

    fn type_union_inner(&mut self) -> Result<(TypeKind, Span), ParseError> {
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
                let path = self.type_path_from_first(name, token.span.clone())?;
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
                            base: path,
                            arguments,
                        },
                        token.span.through(&close),
                    )
                } else {
                    let span = path.span.clone();
                    (TypeKind::Named(path), span)
                }
            }
            TokenKind::Nil => (
                TypeKind::Named(TypePath::single("空", token.span.clone())),
                token.span,
            ),
            TokenKind::Class => (
                TypeKind::Named(TypePath::single("类", token.span.clone())),
                token.span,
            ),
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
            TokenKind::Function => (
                TypeKind::Named(TypePath::single("法", token.span.clone())),
                token.span,
            ),
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

    fn type_path(&mut self, message: &str) -> Result<TypePath, ParseError> {
        let (name, span) = self.identifier_token(message)?;
        self.type_path_from_first(name, span)
    }

    fn type_path_from_first(&mut self, name: String, span: Span) -> Result<TypePath, ParseError> {
        let mut segments = vec![TypePathSegment { name, span }];
        while self.matches(&TokenKind::Dot) {
            let (name, span) = self.identifier_token("类型路径的点号之后须有标识符")?;
            segments.push(TypePathSegment { name, span });
        }
        Ok(TypePath::new(segments))
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

    fn with_statement_depth<T>(
        &mut self,
        parse: impl FnOnce(&mut Self) -> Result<T, ParseError>,
    ) -> Result<T, ParseError> {
        if self.statement_depth >= MAX_SYNTAX_DEPTH {
            return Err(self.error_here(SYNTAX_DEPTH_ERROR));
        }
        self.statement_depth += 1;
        let result = parse(self);
        self.statement_depth -= 1;
        result
    }

    fn with_expression_depth<T>(
        &mut self,
        parse: impl FnOnce(&mut Self) -> Result<T, ParseError>,
    ) -> Result<T, ParseError> {
        if self.expression_depth >= MAX_SYNTAX_DEPTH {
            return Err(self.error_here(SYNTAX_DEPTH_ERROR));
        }
        self.expression_depth += 1;
        let result = parse(self);
        self.expression_depth -= 1;
        result
    }

    fn with_type_depth<T>(
        &mut self,
        parse: impl FnOnce(&mut Self) -> Result<T, ParseError>,
    ) -> Result<T, ParseError> {
        if self.type_depth >= MAX_SYNTAX_DEPTH {
            return Err(self.error_here(SYNTAX_DEPTH_ERROR));
        }
        self.type_depth += 1;
        let result = parse(self);
        self.type_depth -= 1;
        result
    }

    fn parsed_expr(
        &self,
        kind: ExprKind,
        span: Span,
        depth: usize,
    ) -> Result<ParsedExpr, ParseError> {
        if depth > MAX_SYNTAX_DEPTH {
            return Err(ParseError {
                message: SYNTAX_DEPTH_ERROR.into(),
                line: span.line,
                column: span.column,
                span,
            });
        }
        Ok(ParsedExpr {
            expr: Expr::new(kind, span),
            depth,
        })
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
    fn parses_super_calls_and_type_tests() {
        let statements = parse(
            lexer::scan(
                "类 人 承 生灵 则 法 自述（）：文 则 令 值：数|文 为「」；若 值 是 文 则 归 父.自述（）；终 归「」；终 终",
            )
            .unwrap(),
        )
        .unwrap();
        let StmtKind::Class { methods, .. } = &statements[0].kind else {
            panic!("expected class");
        };
        let StmtKind::Function { body, .. } = &methods[0].kind else {
            panic!("expected method");
        };
        let StmtKind::If { condition, .. } = &body[1].kind else {
            panic!("expected if");
        };
        assert!(matches!(condition.kind, ExprKind::TypeTest { .. }));
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
            matches!(&statements[1].kind, StmtKind::Class { protocols, fields, methods, .. } if protocols.len() == 1 && protocols[0].is_single("可命名") && fields.len() == 2 && methods[0].is_static)
        );
    }

    #[test]
    fn parses_qualified_types_in_every_recursive_position() {
        let source = r#"
            公 引「base.yx」为 基础；
            公 类 按钮 承 基础.视图 纳 基础.可描述，协议库.可点击 则
                公 域 内容：基础.视图?；
                公 法 转换（输入：列<基础.视图|基础.窗口>，操作：法（基础.视图，列<基础.按钮>）：基础.窗口）：任务<基础.视图> 则
                    若 此.内容 是 基础.按钮 则 归 操作（此.内容，输入）；终
                    归 此.内容；
                终
            终
        "#;
        let statements = parse(lexer::scan(source).unwrap()).unwrap();
        assert!(statements[0].public);
        assert!(matches!(statements[0].kind, StmtKind::Import { .. }));
        let StmtKind::Class {
            superclass,
            protocols,
            fields,
            methods,
            ..
        } = &statements[1].kind
        else {
            panic!("expected class")
        };
        assert_eq!(superclass.as_ref().unwrap().to_string(), "基础.视图");
        assert_eq!(superclass.as_ref().unwrap().segments.len(), 2);
        assert_eq!(protocols[0].to_string(), "基础.可描述");
        assert_eq!(protocols[1].to_string(), "协议库.可点击");
        assert_eq!(fields[0].type_ref.name, "基础.视图?");
        let StmtKind::Function {
            params,
            return_type,
            body,
            ..
        } = &methods[0].kind
        else {
            panic!("expected method")
        };
        assert_eq!(
            params[0].type_ref.as_ref().unwrap().name,
            "列<基础.视图|基础.窗口>"
        );
        assert_eq!(
            params[1].type_ref.as_ref().unwrap().name,
            "法（基础.视图，列<基础.按钮>）：基础.窗口"
        );
        assert_eq!(return_type.as_ref().unwrap().name, "任务<基础.视图>");
        let StmtKind::If { condition, .. } = &body[0].kind else {
            panic!("expected type-test branch")
        };
        let ExprKind::TypeTest { type_ref, .. } = &condition.kind else {
            panic!("expected type test")
        };
        assert_eq!(type_ref.name, "基础.按钮");
        assert_eq!(type_ref.span.source.name, "<文句>");
    }

    #[test]
    fn qualified_type_errors_point_at_the_broken_segment() {
        let error = parse(lexer::scan("定 根：基础. 为 空；").unwrap()).unwrap_err();
        assert_eq!(error.message, "类型路径的点号之后须有标识符");
        assert_eq!(error.span.column, 9);

        let error = parse(lexer::scan("类 按钮 承 基础. 则 终").unwrap()).unwrap_err();
        assert_eq!(error.message, "类型路径的点号之后须有标识符");
        assert_eq!(error.span.column, 12);
    }

    #[test]
    fn public_import_is_top_level_only() {
        let statements = parse(lexer::scan("公 引「views.yx」为 视图；").unwrap()).unwrap();
        assert!(statements[0].public);
        assert!(matches!(statements[0].kind, StmtKind::Import { .. }));

        let error =
            parse(lexer::scan("若 真 则 公 引「views.yx」为 视图；终").unwrap()).unwrap_err();
        assert_eq!(error.message, "“公 引”只可用于模块顶层");
        assert_eq!(error.span.column, 7);
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

    #[test]
    fn accepts_syntax_at_the_depth_limit() {
        let list_depth = MAX_SYNTAX_DEPTH - 1;
        let sources = [
            format!("言 {}1{}；", "[".repeat(list_depth), "]".repeat(list_depth)),
            format!("言 {}1；", "-".repeat(MAX_SYNTAX_DEPTH - 1)),
            format!("言 {}1；", "1 加 ".repeat(MAX_SYNTAX_DEPTH - 1)),
            format!("言 值{}；", ".成员".repeat(MAX_SYNTAX_DEPTH - 1)),
            format!(
                "定 值：{}数{} 为 1；",
                "列<".repeat(MAX_SYNTAX_DEPTH - 1),
                ">".repeat(MAX_SYNTAX_DEPTH - 1)
            ),
            format!(
                "{}言 1；{}",
                "若 真 则 ".repeat(MAX_SYNTAX_DEPTH - 1),
                "终 ".repeat(MAX_SYNTAX_DEPTH - 1)
            ),
            format!(
                "{}言 {}1{}；{}",
                "若 真 则 ".repeat(MAX_SYNTAX_DEPTH - 1),
                "[".repeat(MAX_SYNTAX_DEPTH - 1),
                "]".repeat(MAX_SYNTAX_DEPTH - 1),
                "终 ".repeat(MAX_SYNTAX_DEPTH - 1)
            ),
        ];

        for source in sources {
            parse(lexer::scan(&source).unwrap()).unwrap();
            let statements = crate::parse(&source).unwrap();
            let formatted = crate::formatter::format(&statements);
            crate::parse(&formatted).unwrap();
        }
    }

    #[test]
    fn rejects_every_unbounded_syntax_depth_path() {
        let sources = [
            "[".repeat(MAX_SYNTAX_DEPTH + 1),
            format!("言 {}1；", "-".repeat(MAX_SYNTAX_DEPTH)),
            format!("言 {}1；", "1 加 ".repeat(MAX_SYNTAX_DEPTH)),
            format!("言 值{}；", ".成员".repeat(MAX_SYNTAX_DEPTH)),
            format!(
                "定 值：{}数{} 为 1；",
                "列<".repeat(MAX_SYNTAX_DEPTH),
                ">".repeat(MAX_SYNTAX_DEPTH)
            ),
            format!(
                "{}言 1；{}",
                "若 真 则 ".repeat(MAX_SYNTAX_DEPTH),
                "终 ".repeat(MAX_SYNTAX_DEPTH)
            ),
        ];

        for source in sources {
            let error = parse(lexer::scan(&source).unwrap()).unwrap_err();
            assert_eq!(error.message, SYNTAX_DEPTH_ERROR, "source: {source}");
        }
    }
}
