use crate::ast::{Expr, ExprKind, Stmt, StmtKind};
use crate::source::Span;
use std::collections::HashSet;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticError {
    pub message: String,
    pub span: Span,
}

impl fmt::Display for SemanticError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.span.render("语义有误", &self.message))
    }
}

impl std::error::Error for SemanticError {}

pub fn resolve(statements: &[Stmt]) -> Result<(), SemanticError> {
    Resolver {
        function_depth: 0,
        class_depth: 0,
    }
    .scope(statements, &[])
}

struct Resolver {
    function_depth: usize,
    class_depth: usize,
}

impl Resolver {
    fn scope(&mut self, statements: &[Stmt], initial: &[String]) -> Result<(), SemanticError> {
        let mut names: HashSet<String> = initial.iter().cloned().collect();
        for statement in statements {
            if let Some((name, span)) = declared_name(statement)
                && !names.insert(name.to_owned())
            {
                return Err(self.error(format!("同一作用域重复声明“{name}”"), span.clone()));
            }
            self.statement(statement)?;
        }
        Ok(())
    }

    fn statement(&mut self, statement: &Stmt) -> Result<(), SemanticError> {
        match &statement.kind {
            StmtKind::Let { value, .. } | StmtKind::Throw(value) | StmtKind::Print(value) => {
                self.expression(value)
            }
            StmtKind::Set { target, value } => {
                self.expression(target)?;
                self.expression(value)
            }
            StmtKind::Expression(expression) => self.expression(expression),
            StmtKind::If {
                condition,
                then_branch,
                else_branch,
            } => {
                self.expression(condition)?;
                self.scope(then_branch, &[])?;
                self.scope(else_branch, &[])
            }
            StmtKind::While { condition, body } => {
                self.expression(condition)?;
                self.scope(body, &[])
            }
            StmtKind::For {
                name,
                iterable,
                body,
                ..
            } => {
                self.expression(iterable)?;
                self.scope(body, std::slice::from_ref(name))
            }
            StmtKind::Function {
                params, body, name, ..
            } => {
                let mut names = HashSet::new();
                for parameter in params {
                    if !names.insert(parameter.name.clone()) {
                        return Err(self.error(
                            format!("法“{name}”重复使用参数“{}”", parameter.name),
                            parameter.span.clone(),
                        ));
                    }
                }
                let params: Vec<String> = params.iter().map(|param| param.name.clone()).collect();
                self.function_depth += 1;
                let result = self.scope(body, &params);
                self.function_depth -= 1;
                result
            }
            StmtKind::Class {
                name,
                superclass,
                fields,
                methods,
                ..
            } => {
                if superclass.as_ref() == Some(name) {
                    return Err(self.error("类不可承自身", statement.span.clone()));
                }
                let mut member_names = HashSet::new();
                for field in fields {
                    if !member_names.insert(&field.name) {
                        return Err(self.error(
                            format!("类“{name}”重复声明成员“{}”", field.name),
                            field.span.clone(),
                        ));
                    }
                    if let Some(initial) = &field.initial {
                        self.expression(initial)?;
                    }
                }
                for method in methods {
                    let StmtKind::Function {
                        name: method_name, ..
                    } = &method.kind
                    else {
                        continue;
                    };
                    if !member_names.insert(method_name) {
                        return Err(self.error(
                            format!("类“{name}”重复声明成员“{method_name}”"),
                            method.span.clone(),
                        ));
                    }
                }
                self.class_depth += 1;
                let result = methods.iter().try_for_each(|method| self.statement(method));
                self.class_depth -= 1;
                result
            }
            StmtKind::Protocol {
                name,
                fields,
                methods,
            } => {
                let mut members = HashSet::new();
                for field in fields {
                    if field.initial.is_some() {
                        return Err(self.error("协之域不可有初值", field.span.clone()));
                    }
                    if !members.insert(&field.name) {
                        return Err(self.error(
                            format!("协“{name}”重复声明成员“{}”", field.name),
                            field.span.clone(),
                        ));
                    }
                }
                for method in methods {
                    let StmtKind::Function {
                        name: method_name, ..
                    } = &method.kind
                    else {
                        continue;
                    };
                    if !members.insert(method_name) {
                        return Err(self.error(
                            format!("协“{name}”重复声明成员“{method_name}”"),
                            method.span.clone(),
                        ));
                    }
                    self.statement(method)?;
                }
                Ok(())
            }
            StmtKind::Import { .. } => Ok(()),
            StmtKind::Try {
                try_branch,
                error_name,
                catch_branch,
            } => {
                self.scope(try_branch, &[])?;
                self.scope(catch_branch, std::slice::from_ref(error_name))
            }
            StmtKind::Return(expression) => {
                if self.function_depth == 0 {
                    return Err(self.error("“归”只能用于法之内", statement.span.clone()));
                }
                if let Some(expression) = expression {
                    self.expression(expression)?;
                }
                Ok(())
            }
        }
    }

    fn expression(&mut self, expression: &Expr) -> Result<(), SemanticError> {
        match &expression.kind {
            ExprKind::Literal(_) | ExprKind::Variable(_) => Ok(()),
            ExprKind::This => {
                if self.class_depth == 0 {
                    Err(self.error("“此”只能用于类之法内", expression.span.clone()))
                } else {
                    Ok(())
                }
            }
            ExprKind::List(items) | ExprKind::Tuple(items) => {
                items.iter().try_for_each(|item| self.expression(item))
            }
            ExprKind::Map(entries) => entries.iter().try_for_each(|(key, value)| {
                self.expression(key)?;
                self.expression(value)
            }),
            ExprKind::Unary { right, .. } => self.expression(right),
            ExprKind::Await { task } => self.expression(task),
            ExprKind::Binary { left, right, .. } => {
                self.expression(left)?;
                self.expression(right)
            }
            ExprKind::Call { callee, arguments } => {
                self.expression(callee)?;
                arguments
                    .iter()
                    .try_for_each(|argument| self.expression(argument))
            }
            ExprKind::Get { object, .. } => self.expression(object),
            ExprKind::Index { object, index } => {
                self.expression(object)?;
                self.expression(index)
            }
            ExprKind::Slice { object, start, end } => {
                self.expression(object)?;
                if let Some(start) = start {
                    self.expression(start)?;
                }
                if let Some(end) = end {
                    self.expression(end)?;
                }
                Ok(())
            }
        }
    }

    fn error(&self, message: impl Into<String>, span: Span) -> SemanticError {
        SemanticError {
            message: message.into(),
            span,
        }
    }
}

fn declared_name(statement: &Stmt) -> Option<(&str, &Span)> {
    match &statement.kind {
        StmtKind::Let { name, .. }
        | StmtKind::Function { name, .. }
        | StmtKind::Class { name, .. }
        | StmtKind::Protocol { name, .. } => Some((name, &statement.span)),
        StmtKind::Import { alias, .. } => Some((alias, &statement.span)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{lexer, parser};

    fn statements(source: &str) -> Vec<Stmt> {
        parser::parse(lexer::scan(source).unwrap()).unwrap()
    }

    #[test]
    fn rejects_return_outside_function_with_source() {
        let error = resolve(&statements("归 1；")).unwrap_err();
        assert!(error.message.contains("法之内"));
        assert!(error.to_string().contains("归 1；"));
    }

    #[test]
    fn rejects_this_outside_class() {
        let error = resolve(&statements("言 此.姓名；")).unwrap_err();
        assert!(error.message.contains("类之法内"));
    }

    #[test]
    fn permits_this_in_nested_method_function() {
        let source = "类 人 则 法 取（）则 法 内（）则 归 此.姓名；终 归 内；终 终";
        resolve(&statements(source)).unwrap();
    }
}
