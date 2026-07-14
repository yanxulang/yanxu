//! 言序源码格式化器。

use crate::ast::{Expr, ExprKind, FieldDecl, Literal, Stmt, StmtKind, TypeRef, Visibility};
use crate::token::TokenKind;

pub fn format(statements: &[Stmt]) -> String {
    let mut formatter = Formatter {
        output: String::new(),
    };
    for (index, statement) in statements.iter().enumerate() {
        formatter.statement(statement, 0);
        if index + 1 < statements.len() {
            formatter.output.push('\n');
        }
    }
    formatter.output
}

struct Formatter {
    output: String,
}

impl Formatter {
    fn statement(&mut self, statement: &Stmt, depth: usize) {
        self.indent(depth);
        if statement.public {
            self.output.push_str("公 ");
        }
        match &statement.kind {
            StmtKind::Let {
                name,
                type_ref,
                value,
                mutable,
            } => {
                self.output.push_str(if *mutable { "令 " } else { "定 " });
                self.output.push_str(name);
                self.type_ref(type_ref.as_ref());
                self.output.push_str(" 为 ");
                self.expression(value);
                self.output.push('；');
            }
            StmtKind::Set { target, value } => {
                self.output.push_str("置 ");
                self.expression(target);
                self.output.push_str(" 为 ");
                self.expression(value);
                self.output.push('；');
            }
            StmtKind::Print(expression) => {
                self.output.push_str("言 ");
                self.expression(expression);
                self.output.push('；');
            }
            StmtKind::Expression(expression) => {
                self.expression(expression);
                self.output.push('；');
            }
            StmtKind::If {
                condition,
                then_branch,
                else_branch,
            } => {
                self.output.push_str("若 ");
                self.expression(condition);
                self.output.push_str(" 则\n");
                self.block(then_branch, depth + 1);
                if !else_branch.is_empty() {
                    self.indent(depth);
                    self.output.push_str("否则\n");
                    self.block(else_branch, depth + 1);
                }
                self.indent(depth);
                self.output.push_str("终\n");
            }
            StmtKind::While { condition, body } => {
                self.output.push_str("当 ");
                self.expression(condition);
                self.output.push_str(" 则\n");
                self.block(body, depth + 1);
                self.indent(depth);
                self.output.push_str("终\n");
            }
            StmtKind::For {
                name,
                type_ref,
                iterable,
                body,
            } => {
                self.output.push_str("逐 ");
                self.output.push_str(name);
                self.type_ref(type_ref.as_ref());
                self.output.push_str(" 于 ");
                self.expression(iterable);
                self.output.push_str(" 则\n");
                self.block(body, depth + 1);
                self.indent(depth);
                self.output.push_str("终\n");
            }
            StmtKind::Function {
                name,
                params,
                return_type,
                body,
                is_async,
            } => {
                if *is_async {
                    self.output.push_str("异 ");
                }
                self.output.push_str("法 ");
                self.output.push_str(name);
                self.output.push('（');
                for (index, param) in params.iter().enumerate() {
                    if index > 0 {
                        self.output.push('，');
                    }
                    self.output.push_str(&param.name);
                    self.type_ref(param.type_ref.as_ref());
                }
                self.output.push('）');
                self.type_ref(return_type.as_ref());
                self.output.push_str(" 则\n");
                self.block(body, depth + 1);
                self.indent(depth);
                self.output.push_str("终\n");
            }
            StmtKind::Class {
                name,
                superclass,
                protocols,
                fields,
                methods,
            } => {
                self.output.push_str("类 ");
                self.output.push_str(name);
                if let Some(superclass) = superclass {
                    self.output.push_str(" 承 ");
                    self.output.push_str(superclass);
                }
                if !protocols.is_empty() {
                    self.output.push_str(" 纳 ");
                    self.output.push_str(&protocols.join("，"));
                }
                self.output.push_str(" 则\n");
                for field in fields {
                    self.field(field, depth + 1);
                }
                for method in methods {
                    self.class_method(method, depth + 1);
                }
                self.indent(depth);
                self.output.push_str("终\n");
            }
            StmtKind::Protocol {
                name,
                fields,
                methods,
            } => {
                self.output.push_str("协 ");
                self.output.push_str(name);
                self.output.push_str(" 则\n");
                for field in fields {
                    self.field(field, depth + 1);
                }
                for method in methods {
                    self.protocol_method(method, depth + 1);
                }
                self.indent(depth);
                self.output.push_str("终\n");
            }
            StmtKind::Import { path, alias } => {
                self.output.push_str("引「");
                self.output.push_str(&escape(path));
                self.output.push_str("」为 ");
                self.output.push_str(alias);
                self.output.push('；');
            }
            StmtKind::Try {
                try_branch,
                error_name,
                catch_branch,
            } => {
                self.output.push_str("试 则\n");
                self.block(try_branch, depth + 1);
                self.indent(depth);
                self.output.push_str("救 ");
                self.output.push_str(error_name);
                self.output.push_str(" 则\n");
                self.block(catch_branch, depth + 1);
                self.indent(depth);
                self.output.push_str("终\n");
            }
            StmtKind::Throw(expression) => {
                self.output.push_str("抛 ");
                self.expression(expression);
                self.output.push('；');
            }
            StmtKind::Return(expression) => {
                self.output.push('归');
                if let Some(expression) = expression {
                    self.output.push(' ');
                    self.expression(expression);
                }
                self.output.push('；');
            }
        }
        if !self.output.ends_with('\n') {
            self.output.push('\n');
        }
    }

    fn block(&mut self, statements: &[Stmt], depth: usize) {
        for statement in statements {
            self.statement(statement, depth);
        }
    }

    fn field(&mut self, field: &FieldDecl, depth: usize) {
        self.indent(depth);
        if field.visibility == Visibility::Private {
            self.output.push_str("私 ");
        } else {
            self.output.push_str("公 ");
        }
        if field.readonly {
            self.output.push_str("只 ");
        }
        if field.is_static {
            self.output.push_str("静 ");
        }
        self.output.push_str("域 ");
        self.output.push_str(&field.name);
        self.type_ref(Some(&field.type_ref));
        if let Some(initial) = &field.initial {
            self.output.push_str(" 为 ");
            self.expression(initial);
        }
        self.output.push_str("；\n");
    }

    fn class_method(&mut self, method: &Stmt, depth: usize) {
        self.indent(depth);
        if method.member_visibility == Visibility::Private {
            self.output.push_str("私 ");
        } else {
            self.output.push_str("公 ");
        }
        if method.is_static {
            self.output.push_str("静 ");
        }
        self.function_body(method, depth);
    }

    fn protocol_method(&mut self, method: &Stmt, depth: usize) {
        self.indent(depth);
        let StmtKind::Function {
            name,
            params,
            return_type,
            is_async,
            ..
        } = &method.kind
        else {
            return;
        };
        if *is_async {
            self.output.push_str("异 ");
        }
        self.output.push_str("法 ");
        self.output.push_str(name);
        self.parameters(params);
        self.type_ref(return_type.as_ref());
        self.output.push_str("；\n");
    }

    fn function_body(&mut self, method: &Stmt, depth: usize) {
        let StmtKind::Function {
            name,
            params,
            return_type,
            body,
            is_async,
        } = &method.kind
        else {
            return;
        };
        if *is_async {
            self.output.push_str("异 ");
        }
        self.output.push_str("法 ");
        self.output.push_str(name);
        self.parameters(params);
        self.type_ref(return_type.as_ref());
        self.output.push_str(" 则\n");
        self.block(body, depth + 1);
        self.indent(depth);
        self.output.push_str("终\n");
    }

    fn parameters(&mut self, params: &[crate::ast::Parameter]) {
        self.output.push('（');
        for (index, param) in params.iter().enumerate() {
            if index > 0 {
                self.output.push('，');
            }
            self.output.push_str(&param.name);
            self.type_ref(param.type_ref.as_ref());
        }
        self.output.push('）');
    }

    fn expression(&mut self, expression: &Expr) {
        match &expression.kind {
            ExprKind::Literal(literal) => match literal {
                Literal::Number(number) if number.fract() == 0.0 => {
                    self.output.push_str(&format!("{number:.0}"));
                }
                Literal::Number(number) => self.output.push_str(&number.to_string()),
                Literal::String(text) => {
                    self.output.push('「');
                    self.output.push_str(&escape(text));
                    self.output.push('」');
                }
                Literal::Bool(true) => self.output.push('真'),
                Literal::Bool(false) => self.output.push('假'),
                Literal::Nil => self.output.push('空'),
            },
            ExprKind::Variable(name) => self.output.push_str(name),
            ExprKind::This => self.output.push('此'),
            ExprKind::Super { method } => {
                self.output.push_str("父.");
                self.output.push_str(method);
            }
            ExprKind::List(items) => self.items(items, '【', '】'),
            ExprKind::Tuple(items) => self.items(items, '（', '）'),
            ExprKind::Map(entries) => {
                self.output.push('{');
                for (index, (key, value)) in entries.iter().enumerate() {
                    if index > 0 {
                        self.output.push('，');
                    }
                    self.expression(key);
                    self.output.push('：');
                    self.expression(value);
                }
                self.output.push('}');
            }
            ExprKind::Unary { operator, right } => {
                self.output.push_str(operator_text(operator));
                self.output.push(' ');
                self.expression(right);
            }
            ExprKind::Await { task } => {
                self.output.push_str("候 ");
                self.expression(task);
            }
            ExprKind::Binary {
                left,
                operator,
                right,
            } => {
                self.output.push('（');
                self.expression(left);
                self.output.push(' ');
                self.output.push_str(operator_text(operator));
                self.output.push(' ');
                self.expression(right);
                self.output.push('）');
            }
            ExprKind::TypeTest { value, type_ref } => {
                self.output.push('（');
                self.expression(value);
                self.output.push_str(" 是 ");
                self.output.push_str(&type_ref.name);
                self.output.push('）');
            }
            ExprKind::Call { callee, arguments } => {
                self.expression(callee);
                self.items(arguments, '（', '）');
            }
            ExprKind::Get { object, name } => {
                self.expression(object);
                self.output.push('.');
                self.output.push_str(name);
            }
            ExprKind::Index { object, index } => {
                self.expression(object);
                self.output.push('【');
                self.expression(index);
                self.output.push('】');
            }
            ExprKind::Slice { object, start, end } => {
                self.expression(object);
                self.output.push('【');
                if let Some(start) = start {
                    self.expression(start);
                }
                self.output.push('：');
                if let Some(end) = end {
                    self.expression(end);
                }
                self.output.push('】');
            }
        }
    }

    fn items(&mut self, items: &[Expr], open: char, close: char) {
        self.output.push(open);
        for (index, item) in items.iter().enumerate() {
            if index > 0 {
                self.output.push('，');
            }
            self.expression(item);
        }
        self.output.push(close);
    }

    fn type_ref(&mut self, type_ref: Option<&TypeRef>) {
        if let Some(type_ref) = type_ref {
            self.output.push('：');
            self.output.push_str(&type_ref.name);
        }
    }

    fn indent(&mut self, depth: usize) {
        self.output.push_str(&"    ".repeat(depth));
    }
}

fn escape(text: &str) -> String {
    text.replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('」', "\\」")
}

fn operator_text(operator: &TokenKind) -> &'static str {
    match operator {
        TokenKind::Plus => "加",
        TokenKind::Minus => "减",
        TokenKind::Star => "乘",
        TokenKind::Slash => "除",
        TokenKind::Bang | TokenKind::Not => "非",
        TokenKind::EqualEqual => "等于",
        TokenKind::BangEqual => "不等于",
        TokenKind::Greater => "大于",
        TokenKind::GreaterEqual => "不小于",
        TokenKind::Less => "小于",
        TokenKind::LessEqual => "不大于",
        TokenKind::And => "且",
        TokenKind::Or => "或",
        _ => "?",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_is_parseable_and_idempotent() {
        let source = "公 异 法 求和（甲：数|文，乙）则\n若 甲 等于 乙 则 归 甲；否则 归 乙；终\n终\n定 工作：任务<数|文> 为 求和（1，2）；\n言 候 工作；";
        let first = format(&crate::parse(source).unwrap());
        let second = format(&crate::parse(&first).unwrap());
        assert_eq!(first, second);
        assert!(first.starts_with("公 异 法 求和"));
    }
}
