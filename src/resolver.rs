use crate::ast::{Expr, Stmt};
use std::collections::HashSet;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticError {
    pub message: String,
}

impl fmt::Display for SemanticError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
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
            if let Some(name) = declared_name(statement)
                && !names.insert(name.to_owned())
            {
                return Err(self.error(format!("同一作用域重复声明“{name}”")));
            }
            self.statement(statement)?;
        }
        Ok(())
    }

    fn statement(&mut self, statement: &Stmt) -> Result<(), SemanticError> {
        match statement {
            Stmt::Let { value, .. } | Stmt::Throw(value) | Stmt::Print(value) => {
                self.expression(value)
            }
            Stmt::Set { target, value } => {
                self.expression(target)?;
                self.expression(value)
            }
            Stmt::Expression(expression) => self.expression(expression),
            Stmt::If {
                condition,
                then_branch,
                else_branch,
            } => {
                self.expression(condition)?;
                self.scope(then_branch, &[])?;
                self.scope(else_branch, &[])
            }
            Stmt::While { condition, body } => {
                self.expression(condition)?;
                self.scope(body, &[])
            }
            Stmt::For {
                name,
                iterable,
                body,
                ..
            } => {
                self.expression(iterable)?;
                self.scope(body, std::slice::from_ref(name))
            }
            Stmt::Function {
                params, body, name, ..
            } => {
                let mut names = HashSet::new();
                for parameter in params {
                    if !names.insert(parameter.name.clone()) {
                        return Err(
                            self.error(format!("法“{name}”重复使用参数“{}”", parameter.name))
                        );
                    }
                }
                let params: Vec<String> = params.iter().map(|param| param.name.clone()).collect();
                self.function_depth += 1;
                let result = self.scope(body, &params);
                self.function_depth -= 1;
                result
            }
            Stmt::Class { name, methods } => {
                let mut method_names = HashSet::new();
                for method in methods {
                    let Stmt::Function {
                        name: method_name, ..
                    } = method
                    else {
                        continue;
                    };
                    if !method_names.insert(method_name) {
                        return Err(self.error(format!("类“{name}”重复声明法“{method_name}”")));
                    }
                }
                self.class_depth += 1;
                let result = methods.iter().try_for_each(|method| self.statement(method));
                self.class_depth -= 1;
                result
            }
            Stmt::Import { .. } => Ok(()),
            Stmt::Try {
                try_branch,
                error_name,
                catch_branch,
            } => {
                self.scope(try_branch, &[])?;
                self.scope(catch_branch, std::slice::from_ref(error_name))
            }
            Stmt::Return(expression) => {
                if self.function_depth == 0 {
                    return Err(self.error("“归”只能用于法之内"));
                }
                if let Some(expression) = expression {
                    self.expression(expression)?;
                }
                Ok(())
            }
        }
    }

    fn expression(&mut self, expression: &Expr) -> Result<(), SemanticError> {
        match expression {
            Expr::Literal(_) | Expr::Variable(_) => Ok(()),
            Expr::This => {
                if self.class_depth == 0 {
                    Err(self.error("“此”只能用于类之法内"))
                } else {
                    Ok(())
                }
            }
            Expr::List(items) => items.iter().try_for_each(|item| self.expression(item)),
            Expr::Map(entries) => entries.iter().try_for_each(|(key, value)| {
                self.expression(key)?;
                self.expression(value)
            }),
            Expr::Unary { right, .. } => self.expression(right),
            Expr::Binary { left, right, .. } => {
                self.expression(left)?;
                self.expression(right)
            }
            Expr::Call { callee, arguments } => {
                self.expression(callee)?;
                arguments
                    .iter()
                    .try_for_each(|argument| self.expression(argument))
            }
            Expr::Get { object, .. } => self.expression(object),
            Expr::Index { object, index } => {
                self.expression(object)?;
                self.expression(index)
            }
        }
    }

    fn error(&self, message: impl Into<String>) -> SemanticError {
        SemanticError {
            message: message.into(),
        }
    }
}

fn declared_name(statement: &Stmt) -> Option<&str> {
    match statement {
        Stmt::Let { name, .. } | Stmt::Function { name, .. } | Stmt::Class { name, .. } => {
            Some(name)
        }
        Stmt::Import { alias, .. } => Some(alias),
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
    fn rejects_return_outside_function() {
        let error = resolve(&statements("归 1；")).unwrap_err();
        assert!(error.message.contains("法之内"));
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
