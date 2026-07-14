//! 面向编辑器的轻量语义索引。
//!
//! 该索引复用已解析 AST 和词法 token，记录声明、词法作用域、引用、类型摘要与
//! 声明注释。它不执行程序，也不替代完整类型检查器；LSP、REPL 等交互工具可在
//! 一次构建后共享查询结果。

use crate::ast::{Expr, ExprKind, Literal, Parameter, Stmt, StmtKind, TypeRef};
use crate::source::Span;
use crate::token::{Token, TokenKind};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolKind {
    Module,
    Class,
    Protocol,
    Function,
    Method,
    Field,
    Variable,
    Constant,
    Parameter,
}

impl SymbolKind {
    pub fn lsp_kind(self) -> u8 {
        match self {
            Self::Module => 2,
            Self::Class => 5,
            Self::Method => 6,
            Self::Field => 8,
            Self::Protocol => 11,
            Self::Function => 12,
            Self::Variable | Self::Parameter => 13,
            Self::Constant => 14,
        }
    }

    pub fn completion_kind(self) -> u8 {
        match self {
            Self::Method => 2,
            Self::Function => 3,
            Self::Field => 5,
            Self::Variable | Self::Parameter => 6,
            Self::Class => 7,
            Self::Protocol => 8,
            Self::Module => 9,
            Self::Constant => 21,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Module => "模块",
            Self::Class => "类",
            Self::Protocol => "协",
            Self::Function => "法",
            Self::Method => "方法",
            Self::Field => "域",
            Self::Variable => "变量",
            Self::Constant => "常量",
            Self::Parameter => "参数",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Symbol {
    pub id: usize,
    pub name: String,
    pub kind: SymbolKind,
    pub declaration: Span,
    pub selection: Span,
    pub detail: String,
    pub type_name: String,
    pub documentation: Option<String>,
    pub container: Option<String>,
    scope: Scope,
    depth: usize,
    member: bool,
}

#[derive(Debug, Clone)]
pub struct Occurrence {
    pub symbol_id: usize,
    pub span: Span,
    pub declaration: bool,
}

#[derive(Debug, Clone, Copy)]
struct Point {
    line: usize,
    column: usize,
}

#[derive(Debug, Clone, Copy)]
struct Scope {
    start: Point,
    end: Point,
}

impl Scope {
    fn document() -> Self {
        Self {
            start: Point { line: 1, column: 1 },
            end: Point {
                line: usize::MAX,
                column: usize::MAX,
            },
        }
    }

    fn from_span(span: &Span) -> Self {
        Self {
            start: point(span),
            end: Point {
                line: span.end_line,
                column: span.end_column,
            },
        }
    }

    fn contains(self, line: usize, column: usize) -> bool {
        position_at_or_after(line, column, self.start) && position_before(line, column, self.end)
    }

    fn size(self) -> (usize, usize) {
        (
            self.end.line.saturating_sub(self.start.line),
            self.end.column.saturating_sub(self.start.column),
        )
    }
}

pub struct SemanticIndex {
    source: String,
    tokens: Vec<Token>,
    symbols: Vec<Symbol>,
    occurrences: Vec<Occurrence>,
}

impl SemanticIndex {
    pub fn build(source: &str, name: &str) -> Result<Self, crate::YanxuError> {
        let tokens = crate::lexer::scan_named(source, name).map_err(crate::YanxuError::Lex)?;
        let statements = crate::parser::parse(tokens.clone()).map_err(crate::YanxuError::Parse)?;
        crate::resolver::resolve(&statements).map_err(crate::YanxuError::Semantic)?;
        let mut builder = Builder {
            source,
            tokens: &tokens,
            symbols: Vec::new(),
            used_declarations: HashSet::new(),
        };
        builder.statements(&statements, Scope::document(), 0, None, false);
        let symbols = builder.symbols;
        let occurrences = resolve_occurrences(&tokens, &symbols);
        Ok(Self {
            source: source.into(),
            tokens,
            symbols,
            occurrences,
        })
    }

    pub fn symbols(&self) -> &[Symbol] {
        &self.symbols
    }

    pub fn occurrences(&self) -> &[Occurrence] {
        &self.occurrences
    }

    pub fn symbol_at(&self, line: usize, column: usize) -> Option<&Symbol> {
        let occurrence = self.occurrences.iter().find(|occurrence| {
            occurrence.span.line == line
                && occurrence.span.column <= column
                && column < occurrence.span.end_column
        })?;
        self.symbols.get(occurrence.symbol_id)
    }

    pub fn references(&self, symbol_id: usize, include_declaration: bool) -> Vec<&Occurrence> {
        self.occurrences
            .iter()
            .filter(|occurrence| {
                occurrence.symbol_id == symbol_id
                    && (include_declaration || !occurrence.declaration)
            })
            .collect()
    }

    pub fn visible_symbols(&self, line: usize, column: usize) -> Vec<&Symbol> {
        let after_dot = token_before(&self.tokens, line, column)
            .is_some_and(|token| matches!(token.kind, TokenKind::Dot));
        let mut by_name = HashMap::<&str, &Symbol>::new();
        for symbol in &self.symbols {
            if !symbol.scope.contains(line, column) || (after_dot && !symbol.member) {
                continue;
            }
            let replace = by_name.get(symbol.name.as_str()).is_none_or(|existing| {
                symbol.depth > existing.depth
                    || (symbol.depth == existing.depth
                        && position_before_span(&existing.selection, &symbol.selection))
            });
            if replace {
                by_name.insert(&symbol.name, symbol);
            }
        }
        let mut values = by_name.into_values().collect::<Vec<_>>();
        values.sort_by(|left, right| left.name.cmp(&right.name));
        values
    }

    pub fn source(&self) -> &str {
        &self.source
    }
}

struct Builder<'a> {
    source: &'a str,
    tokens: &'a [Token],
    symbols: Vec<Symbol>,
    used_declarations: HashSet<(usize, usize)>,
}

impl Builder<'_> {
    fn statements(
        &mut self,
        statements: &[Stmt],
        scope: Scope,
        depth: usize,
        container: Option<&str>,
        methods: bool,
    ) {
        for statement in statements {
            match &statement.kind {
                StmtKind::Let {
                    name,
                    type_ref,
                    value,
                    mutable,
                } => {
                    let type_name = type_ref
                        .as_ref()
                        .map_or_else(|| infer_expr(value), |ty| ty.name.clone());
                    self.add(
                        name,
                        if *mutable {
                            SymbolKind::Variable
                        } else {
                            SymbolKind::Constant
                        },
                        &statement.span,
                        scope,
                        depth,
                        type_name.clone(),
                        format!("{} {name}：{type_name}", if *mutable { "令" } else { "定" }),
                        container,
                        methods,
                    );
                }
                StmtKind::For {
                    name,
                    type_ref,
                    body,
                    ..
                } => {
                    let body_scope = block_scope(body, &statement.span);
                    self.add(
                        name,
                        SymbolKind::Constant,
                        &statement.span,
                        body_scope,
                        depth + 1,
                        type_name(type_ref.as_ref()),
                        format!("逐 {name}"),
                        container,
                        false,
                    );
                    self.statements(body, body_scope, depth + 1, container, false);
                }
                StmtKind::Function {
                    name,
                    params,
                    return_type,
                    body,
                    is_async,
                    ..
                } => {
                    let signature =
                        function_signature(name, params, return_type.as_ref(), *is_async);
                    self.add(
                        name,
                        if methods {
                            SymbolKind::Method
                        } else {
                            SymbolKind::Function
                        },
                        &statement.span,
                        scope,
                        depth,
                        function_type(params, return_type.as_ref(), *is_async),
                        signature,
                        container,
                        methods,
                    );
                    let function_scope = Scope::from_span(&statement.span);
                    for parameter in params {
                        self.parameter(parameter, function_scope, depth + 1, container);
                    }
                    self.statements(body, function_scope, depth + 1, container, false);
                }
                StmtKind::Class {
                    name,
                    fields,
                    methods,
                    ..
                } => {
                    self.add(
                        name,
                        SymbolKind::Class,
                        &statement.span,
                        scope,
                        depth,
                        name.clone(),
                        format!("类 {name}"),
                        container,
                        false,
                    );
                    for field in fields {
                        self.add(
                            &field.name,
                            SymbolKind::Field,
                            &field.span,
                            Scope::document(),
                            depth + 1,
                            field.type_ref.name.clone(),
                            format!("域 {}：{}", field.name, field.type_ref.name),
                            Some(name),
                            true,
                        );
                    }
                    self.statements(methods, Scope::document(), depth + 1, Some(name), true);
                }
                StmtKind::Protocol {
                    name,
                    fields,
                    methods,
                } => {
                    self.add(
                        name,
                        SymbolKind::Protocol,
                        &statement.span,
                        scope,
                        depth,
                        name.clone(),
                        format!("协 {name}"),
                        container,
                        false,
                    );
                    for field in fields {
                        self.add(
                            &field.name,
                            SymbolKind::Field,
                            &field.span,
                            Scope::document(),
                            depth + 1,
                            field.type_ref.name.clone(),
                            format!("域 {}：{}", field.name, field.type_ref.name),
                            Some(name),
                            true,
                        );
                    }
                    self.statements(methods, Scope::document(), depth + 1, Some(name), true);
                }
                StmtKind::Import { alias, path } => self.add(
                    alias,
                    SymbolKind::Module,
                    &statement.span,
                    scope,
                    depth,
                    "模块".into(),
                    format!("引「{path}」为 {alias}"),
                    container,
                    false,
                ),
                StmtKind::If {
                    then_branch,
                    else_branch,
                    ..
                } => {
                    self.nested(then_branch, &statement.span, depth, container);
                    self.nested(else_branch, &statement.span, depth, container);
                }
                StmtKind::While { body, .. } => {
                    self.nested(body, &statement.span, depth, container)
                }
                StmtKind::Try {
                    try_branch,
                    error_name,
                    catch_branch,
                } => {
                    self.nested(try_branch, &statement.span, depth, container);
                    let catch_scope = block_scope(catch_branch, &statement.span);
                    self.add(
                        error_name,
                        SymbolKind::Constant,
                        &statement.span,
                        catch_scope,
                        depth + 1,
                        "误".into(),
                        format!("救 {error_name}：误"),
                        container,
                        false,
                    );
                    self.statements(catch_branch, catch_scope, depth + 1, container, false);
                }
                StmtKind::Set { .. }
                | StmtKind::Print(_)
                | StmtKind::Expression(_)
                | StmtKind::Throw(_)
                | StmtKind::Return(_) => {}
            }
        }
    }

    fn nested(
        &mut self,
        statements: &[Stmt],
        fallback: &Span,
        depth: usize,
        container: Option<&str>,
    ) {
        let scope = block_scope(statements, fallback);
        self.statements(statements, scope, depth + 1, container, false);
    }

    fn parameter(
        &mut self,
        parameter: &Parameter,
        scope: Scope,
        depth: usize,
        container: Option<&str>,
    ) {
        let type_name = type_name(parameter.type_ref.as_ref());
        self.add(
            &parameter.name,
            SymbolKind::Parameter,
            &parameter.span,
            scope,
            depth,
            type_name.clone(),
            format!("参数 {}：{type_name}", parameter.name),
            container,
            false,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn add(
        &mut self,
        name: &str,
        kind: SymbolKind,
        declaration: &Span,
        scope: Scope,
        depth: usize,
        type_name: String,
        detail: String,
        container: Option<&str>,
        member: bool,
    ) {
        let Some(selection) = self.find_declaration(name, declaration) else {
            return;
        };
        let id = self.symbols.len();
        self.symbols.push(Symbol {
            id,
            name: name.into(),
            kind,
            declaration: declaration.clone(),
            documentation: declaration_comment(self.source, selection.line),
            selection,
            detail,
            type_name,
            container: container.map(str::to_owned),
            scope,
            depth,
            member,
        });
    }

    fn find_declaration(&mut self, name: &str, span: &Span) -> Option<Span> {
        let token = self.tokens.iter().find(|token| {
            matches!(&token.kind, TokenKind::Identifier(value) if value == name)
                && span_contains(span, &token.span)
                && !self
                    .used_declarations
                    .contains(&(token.span.line, token.span.column))
        })?;
        self.used_declarations
            .insert((token.span.line, token.span.column));
        Some(token.span.clone())
    }
}

fn resolve_occurrences(tokens: &[Token], symbols: &[Symbol]) -> Vec<Occurrence> {
    let declarations = symbols
        .iter()
        .map(|symbol| ((symbol.selection.line, symbol.selection.column), symbol.id))
        .collect::<HashMap<_, _>>();
    let mut occurrences = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        let TokenKind::Identifier(name) = &token.kind else {
            continue;
        };
        if let Some(symbol_id) = declarations.get(&(token.span.line, token.span.column)) {
            occurrences.push(Occurrence {
                symbol_id: *symbol_id,
                span: token.span.clone(),
                declaration: true,
            });
            continue;
        }
        let property = index > 0 && matches!(tokens[index - 1].kind, TokenKind::Dot);
        let mut candidates = symbols
            .iter()
            .filter(|symbol| {
                symbol.name == *name
                    && symbol.scope.contains(token.span.line, token.span.column)
                    && (!property || symbol.member)
                    && (symbol.member || position_before_span(&symbol.selection, &token.span))
            })
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| {
            right
                .depth
                .cmp(&left.depth)
                .then_with(|| left.scope.size().cmp(&right.scope.size()))
                .then_with(|| position_key(&right.selection).cmp(&position_key(&left.selection)))
        });
        if let Some(symbol) = candidates.first() {
            occurrences.push(Occurrence {
                symbol_id: symbol.id,
                span: token.span.clone(),
                declaration: false,
            });
        }
    }
    occurrences
}

fn function_signature(
    name: &str,
    params: &[Parameter],
    result: Option<&TypeRef>,
    is_async: bool,
) -> String {
    let result = type_name(result);
    format!(
        "{}法 {name}（{}）：{}",
        if is_async { "异 " } else { "" },
        params
            .iter()
            .map(|parameter| format!(
                "{}：{}",
                parameter.name,
                type_name(parameter.type_ref.as_ref())
            ))
            .collect::<Vec<_>>()
            .join("，"),
        if is_async {
            format!("任务<{result}>")
        } else {
            result
        }
    )
}

fn function_type(params: &[Parameter], result: Option<&TypeRef>, is_async: bool) -> String {
    let result = type_name(result);
    format!(
        "法（{}）：{}",
        params
            .iter()
            .map(|parameter| type_name(parameter.type_ref.as_ref()))
            .collect::<Vec<_>>()
            .join("，"),
        if is_async {
            format!("任务<{result}>")
        } else {
            result
        }
    )
}

fn type_name(type_ref: Option<&TypeRef>) -> String {
    type_ref.map_or_else(|| "任意".into(), |ty| ty.name.clone())
}

fn infer_expr(expression: &Expr) -> String {
    match &expression.kind {
        ExprKind::Literal(Literal::Number(_)) => "数".into(),
        ExprKind::Literal(Literal::String(_)) => "文".into(),
        ExprKind::Literal(Literal::Bool(_)) => "理".into(),
        ExprKind::Literal(Literal::Nil) => "空".into(),
        ExprKind::List(items) => format!(
            "列<{}>",
            items.first().map_or_else(|| "任意".into(), infer_expr)
        ),
        ExprKind::Tuple(items) => format!(
            "元<{}>",
            items.iter().map(infer_expr).collect::<Vec<_>>().join("，")
        ),
        ExprKind::Map(entries) => entries.first().map_or_else(
            || "典<任意，任意>".into(),
            |(key, value)| format!("典<{}，{}>", infer_expr(key), infer_expr(value)),
        ),
        _ => "任意".into(),
    }
}

fn declaration_comment(source: &str, line: usize) -> Option<String> {
    let lines = source.lines().collect::<Vec<_>>();
    let mut current = line.saturating_sub(1);
    let mut comments = Vec::new();
    while current > 0 {
        let text = lines.get(current - 1)?.trim();
        let comment = text
            .strip_prefix("///")
            .or_else(|| text.strip_prefix("#:"))
            .map(str::trim);
        match comment {
            Some(comment) => comments.push(comment.to_owned()),
            None if text.is_empty() && comments.is_empty() => current -= 1,
            None => break,
        }
        current -= 1;
    }
    comments.reverse();
    (!comments.is_empty()).then(|| comments.join("\n"))
}

fn block_scope(statements: &[Stmt], fallback: &Span) -> Scope {
    match (statements.first(), statements.last()) {
        (Some(first), Some(last)) => Scope {
            start: point(&first.span),
            end: Point {
                line: last.span.end_line,
                column: last.span.end_column,
            },
        },
        _ => Scope::from_span(fallback),
    }
}

fn span_contains(outer: &Span, inner: &Span) -> bool {
    position_at_or_after(inner.line, inner.column, point(outer))
        && position_before(
            inner.line,
            inner.column,
            Point {
                line: outer.end_line,
                column: outer.end_column,
            },
        )
}

fn token_before(tokens: &[Token], line: usize, column: usize) -> Option<&Token> {
    tokens.iter().rev().find(|token| {
        token.span.line < line || (token.span.line == line && token.span.end_column <= column)
    })
}

fn point(span: &Span) -> Point {
    Point {
        line: span.line,
        column: span.column,
    }
}

fn position_key(span: &Span) -> (usize, usize) {
    (span.line, span.column)
}

fn position_before_span(left: &Span, right: &Span) -> bool {
    position_key(left) < position_key(right)
}

fn position_at_or_after(line: usize, column: usize, point: Point) -> bool {
    (line, column) >= (point.line, point.column)
}

fn position_before(line: usize, column: usize, point: Point) -> bool {
    (line, column) < (point.line, point.column)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_shadowing_members_types_and_comments() {
        let source = r#"
            /// 可显示姓名。
            类 人 则
                域 姓名：文；
                法 显示（前缀：文）：文 则 归 前缀 加 此.姓名；终
            终
            定 前缀：文 为「吾名」；
            定 子：人 为 人（）；
            言 子.显示（前缀）；
        "#;
        let index = SemanticIndex::build(source, "索引.yx").unwrap();
        let person = index
            .symbols()
            .iter()
            .find(|symbol| symbol.name == "人")
            .unwrap();
        assert_eq!(person.kind, SymbolKind::Class);
        assert_eq!(person.documentation.as_deref(), Some("可显示姓名。"));
        let display = index
            .symbols()
            .iter()
            .find(|symbol| symbol.name == "显示")
            .unwrap();
        assert_eq!(display.type_name, "法（文）：文");
        assert_eq!(index.references(display.id, true).len(), 2);
        let prefixes = index
            .symbols()
            .iter()
            .filter(|symbol| symbol.name == "前缀")
            .collect::<Vec<_>>();
        assert_eq!(prefixes.len(), 2);
        assert_ne!(prefixes[0].id, prefixes[1].id);
    }
}
