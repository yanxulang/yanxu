//! 从公开声明生成稳定 Markdown API 文档。

use crate::ast::{Parameter, Stmt, StmtKind, TypeKind, TypeRef, Visibility};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

const BUILTIN_TYPES: &[(&str, &str)] = &[
    ("数", "有限浮点数"),
    ("文", "Unicode 文字"),
    ("字节串", "不可变的任意二进制数据"),
    ("理", "真或假"),
    ("空", "无值"),
    ("列", "可变有序容器"),
    ("元", "不可变定长容器"),
    ("典", "键值映射"),
    ("法", "可调用值"),
    ("遍器", "惰性迭代器"),
    ("误", "结构化错误"),
    ("任务", "可取消的异步计算"),
    ("模块", "模块命名空间"),
    ("任意", "动态未知类型"),
];

pub fn markdown(module_name: &str, statements: &[Stmt]) -> String {
    let context = TypeLinks::new(statements);
    let public = statements
        .iter()
        .filter(|statement| statement.public && declaration_name(statement).is_some())
        .collect::<Vec<_>>();
    let mut output = format!(
        "# {module_name}\n\n> 由 `yanxu 文` 生成。所有锚点由声明类别与名称确定，可跨版本稳定引用。\n\n"
    );
    output.push_str("## 模块索引\n\n");
    if public.is_empty() {
        output.push_str("此模块未声明公开 API。\n\n");
    } else {
        output.push_str("| 名称 | 类别 | 类型 |\n| --- | --- | --- |\n");
        for statement in &public {
            let (name, kind, anchor, ty) = declaration_summary(statement, &context);
            output.push_str(&format!("| [`{name}`](#{anchor}) | {kind} | {ty} |\n"));
        }
        output.push('\n');
    }

    for statement in public {
        render_declaration(&mut output, statement, &context);
    }
    render_builtin_types(&mut output);
    output
}

/// Stable machine-readable API surface used by package tooling and LSP clients.
pub fn api_manifest(module_name: &str, statements: &[Stmt]) -> Value {
    let declarations = statements
        .iter()
        .filter(|statement| statement.public)
        .filter_map(api_declaration)
        .collect::<Vec<_>>();
    json!({
        "format_version": 1,
        "language": "yanxu",
        "module": module_name,
        "declarations": declarations,
    })
}

fn api_declaration(statement: &Stmt) -> Option<Value> {
    let documentation = comment_before(&statement.span).unwrap_or_default();
    match &statement.kind {
        StmtKind::Let {
            name,
            type_ref,
            mutable,
            ..
        } => Some(json!({
            "kind": if *mutable { "variable" } else { "constant" },
            "name": name,
            "type": api_optional_type(type_ref.as_ref()),
            "documentation": documentation,
        })),
        StmtKind::Function {
            name,
            params,
            return_type,
            is_async,
            ..
        } => Some(api_function(
            "function",
            name,
            params,
            return_type.as_ref(),
            *is_async,
            false,
            documentation,
        )),
        StmtKind::Class {
            name,
            superclass,
            protocols,
            fields,
            methods,
        } => Some(json!({
            "kind": "class",
            "name": name,
            "superclass": superclass.as_ref().map(ToString::to_string),
            "protocols": protocols.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "documentation": documentation,
            "fields": fields.iter()
                .filter(|field| field.visibility == Visibility::Public)
                .map(|field| json!({
                    "name": field.name,
                    "type": field.type_ref.name,
                    "readonly": field.readonly,
                    "static": field.is_static,
                    "documentation": comment_before(&field.span).unwrap_or_default(),
                }))
                .collect::<Vec<_>>(),
            "methods": methods.iter()
                .filter(|method| method.member_visibility == Visibility::Public)
                .filter_map(|method| match &method.kind {
                    StmtKind::Function { name, params, return_type, is_async, .. } => Some(api_function(
                        "method", name, params, return_type.as_ref(), *is_async, method.is_static,
                        comment_before(&method.span).unwrap_or_default(),
                    )),
                    _ => None,
                })
                .collect::<Vec<_>>(),
        })),
        StmtKind::Protocol {
            name,
            fields,
            methods,
        } => Some(json!({
            "kind": "protocol",
            "name": name,
            "documentation": documentation,
            "fields": fields.iter().map(|field| json!({
                "name": field.name,
                "type": field.type_ref.name,
            })).collect::<Vec<_>>(),
            "methods": methods.iter().filter_map(|method| match &method.kind {
                StmtKind::Function { name, params, return_type, is_async, .. } => Some(api_function(
                    "method", name, params, return_type.as_ref(), *is_async, method.is_static,
                    comment_before(&method.span).unwrap_or_default(),
                )),
                _ => None,
            }).collect::<Vec<_>>(),
        })),
        _ => None,
    }
}

fn api_function(
    kind: &str,
    name: &str,
    parameters: &[Parameter],
    result: Option<&TypeRef>,
    is_async: bool,
    is_static: bool,
    documentation: String,
) -> Value {
    let parameters = parameters
        .iter()
        .map(|parameter| {
            json!({
                "name": parameter.name,
                "type": api_optional_type(parameter.type_ref.as_ref()),
            })
        })
        .collect::<Vec<_>>();
    let result = api_optional_type(result);
    let signature = format!(
        "法（{}）：{}",
        parameters
            .iter()
            .map(|parameter| parameter["type"].as_str().unwrap_or("任意"))
            .collect::<Vec<_>>()
            .join("，"),
        if is_async {
            format!("任务<{result}>")
        } else {
            result.clone()
        }
    );
    json!({
        "kind": kind,
        "name": name,
        "parameters": parameters,
        "result": result,
        "async": is_async,
        "static": is_static,
        "signature": signature,
        "documentation": documentation,
    })
}

fn api_optional_type(type_ref: Option<&TypeRef>) -> String {
    type_ref.map_or_else(|| "任意".into(), |type_ref| type_ref.name.clone())
}

pub fn markdown_directory(path: impl AsRef<Path>) -> Result<String, String> {
    let root = fs::canonicalize(path.as_ref())
        .map_err(|error| format!("不能定位文档目录“{}”：{error}", path.as_ref().display()))?;
    let mut files = Vec::new();
    visit(&root, &mut files)?;
    files.sort();
    let mut modules = Vec::new();
    for file in files {
        let source = fs::read_to_string(&file)
            .map_err(|error| format!("不能读取“{}”：{error}", file.display()))?;
        let statements = crate::parse_named(&source, file.display().to_string())
            .map_err(|error| error.to_string())?;
        let name = file
            .strip_prefix(&root)
            .unwrap_or(&file)
            .with_extension("")
            .to_string_lossy()
            .replace(std::path::MAIN_SEPARATOR, "/");
        modules.push((name, statements));
    }

    let mut output = "# 言序模块文档\n\n## 模块索引\n\n".to_owned();
    for (name, _) in &modules {
        output.push_str(&format!("- [`{name}`](#模块-{})\n", anchor_text(name)));
    }
    if modules.is_empty() {
        output.push_str("未发现 `.yx` 模块。\n");
    }
    for (name, statements) in &modules {
        output.push_str(&format!(
            "\n<a id=\"模块-{}\"></a>\n\n---\n\n",
            anchor_text(name)
        ));
        output.push_str(&markdown(name, statements));
    }
    Ok(output)
}

pub fn stable_anchor(kind: &str, name: &str) -> String {
    format!("{}-{}", anchor_text(kind), anchor_text(name))
}

fn render_declaration(output: &mut String, statement: &Stmt, context: &TypeLinks) {
    match &statement.kind {
        StmtKind::Let {
            name,
            type_ref,
            mutable,
            ..
        } => {
            let kind = if *mutable { "变量" } else { "常量" };
            heading(output, kind, name, statement);
            output.push_str(&format!(
                "```yanxu\n公 {} {name}{}；\n```\n\n",
                if *mutable { "令" } else { "定" },
                render_type_plain(type_ref.as_ref())
            ));
            output.push_str(&format!(
                "类型：{}\n\n",
                context.render_optional(type_ref.as_ref())
            ));
        }
        StmtKind::Function {
            name,
            params,
            return_type,
            is_async,
            ..
        } => {
            heading(
                output,
                if *is_async { "异法" } else { "法" },
                name,
                statement,
            );
            output.push_str(&format!(
                "```yanxu\n公 {}法 {name}（{}）{}；\n```\n\n",
                if *is_async { "异 " } else { "" },
                params
                    .iter()
                    .map(render_parameter_plain)
                    .collect::<Vec<_>>()
                    .join("，"),
                render_type_plain(return_type.as_ref())
            ));
            output.push_str(&format!(
                "{}：{}\n\n",
                if *is_async {
                    "任务完成值"
                } else {
                    "归值"
                },
                context.render_optional(return_type.as_ref()),
            ));
            render_parameters(output, params, context);
        }
        StmtKind::Class {
            name,
            superclass,
            protocols,
            fields,
            methods,
        } => {
            heading(output, "类", name, statement);
            let inheritance = superclass
                .as_ref()
                .map_or_else(String::new, |parent| format!(" 承 {parent}"));
            let conformance = if protocols.is_empty() {
                String::new()
            } else {
                format!(
                    " 纳 {}",
                    protocols
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join("，")
                )
            };
            output.push_str(&format!(
                "```yanxu\n公 类 {name}{inheritance}{conformance}\n```\n\n"
            ));
            if let Some(parent) = superclass {
                output.push_str(&format!(
                    "父类：{}\n\n",
                    context.render_named(&parent.to_string())
                ));
            }
            for field in fields
                .iter()
                .filter(|field| field.visibility == Visibility::Public)
            {
                let anchor = stable_anchor(&format!("类-{name}-域"), &field.name);
                output.push_str(&format!(
                    "<a id=\"{anchor}\"></a>\n\n### 域 `{}`\n\n",
                    field.name
                ));
                render_comment(output, comment_before(&field.span));
                output.push_str(&format!(
                    "- 类型：{}\n- 属性：{}{}{}\n\n",
                    context.render(&field.type_ref.kind),
                    if field.is_static { "静态" } else { "实例" },
                    if field.readonly { "、只读" } else { "" },
                    if field.visibility == Visibility::Private {
                        "、私有"
                    } else {
                        "、公开"
                    }
                ));
            }
            for method in methods
                .iter()
                .filter(|method| method.member_visibility == Visibility::Public)
            {
                if let StmtKind::Function {
                    name: method_name,
                    params,
                    return_type,
                    is_async,
                    ..
                } = &method.kind
                {
                    let anchor = stable_anchor(&format!("类-{name}-法"), method_name);
                    output.push_str(&format!(
                        "<a id=\"{anchor}\"></a>\n\n### 法 `{method_name}`\n\n"
                    ));
                    render_comment(output, comment_before(&method.span));
                    output.push_str(&format!(
                        "类型：`法`（{}） → {}\n\n",
                        params
                            .iter()
                            .map(|parameter| context.render_optional(parameter.type_ref.as_ref()))
                            .collect::<Vec<_>>()
                            .join("，"),
                        if *is_async {
                            format!("任务<{}>", context.render_optional(return_type.as_ref()))
                        } else {
                            context.render_optional(return_type.as_ref())
                        }
                    ));
                }
            }
        }
        StmtKind::Protocol {
            name,
            fields,
            methods,
        } => {
            heading(output, "协", name, statement);
            for field in fields {
                output.push_str(&format!(
                    "- 域 `{}`：{}\n",
                    field.name,
                    context.render(&field.type_ref.kind)
                ));
            }
            for method in methods {
                if let StmtKind::Function {
                    name,
                    params,
                    return_type,
                    is_async,
                    ..
                } = &method.kind
                {
                    output.push_str(&format!(
                        "- 法 `{name}`（{}）→ {}\n",
                        params
                            .iter()
                            .map(|parameter| context.render_optional(parameter.type_ref.as_ref()))
                            .collect::<Vec<_>>()
                            .join("，"),
                        if *is_async {
                            format!("任务<{}>", context.render_optional(return_type.as_ref()))
                        } else {
                            context.render_optional(return_type.as_ref())
                        }
                    ));
                }
            }
            output.push('\n');
        }
        _ => {}
    }
}

fn heading(output: &mut String, kind: &str, name: &str, statement: &Stmt) {
    let anchor = stable_anchor(kind, name);
    output.push_str(&format!(
        "<a id=\"{anchor}\"></a>\n\n## {kind} `{name}`\n\n"
    ));
    render_comment(output, comment_before(&statement.span));
}

fn render_comment(output: &mut String, comment: Option<String>) {
    if let Some(comment) = comment {
        output.push_str(&comment);
        output.push_str("\n\n");
    }
}

fn render_parameters(output: &mut String, parameters: &[Parameter], context: &TypeLinks) {
    if parameters.is_empty() {
        return;
    }
    output.push_str("参数：\n\n");
    for parameter in parameters {
        output.push_str(&format!(
            "- `{}`：{}\n",
            parameter.name,
            context.render_optional(parameter.type_ref.as_ref())
        ));
    }
    output.push('\n');
}

fn declaration_summary(
    statement: &Stmt,
    context: &TypeLinks,
) -> (String, &'static str, String, String) {
    match &statement.kind {
        StmtKind::Let {
            name,
            type_ref,
            mutable,
            ..
        } => {
            let kind = if *mutable { "变量" } else { "常量" };
            (
                name.clone(),
                kind,
                stable_anchor(kind, name),
                context.render_optional(type_ref.as_ref()),
            )
        }
        StmtKind::Function {
            name,
            params,
            return_type,
            is_async,
            ..
        } => (
            name.clone(),
            "法",
            stable_anchor("法", name),
            format!(
                "`法`（{}）→ {}",
                params
                    .iter()
                    .map(|parameter| context.render_optional(parameter.type_ref.as_ref()))
                    .collect::<Vec<_>>()
                    .join("，"),
                if *is_async {
                    format!("任务<{}>", context.render_optional(return_type.as_ref()))
                } else {
                    context.render_optional(return_type.as_ref())
                }
            ),
        ),
        StmtKind::Class { name, .. } => (
            name.clone(),
            "类",
            stable_anchor("类", name),
            context.render_named(name),
        ),
        StmtKind::Protocol { name, .. } => (
            name.clone(),
            "协",
            stable_anchor("协", name),
            context.render_named(name),
        ),
        _ => unreachable!("filtered to declarations"),
    }
}

fn declaration_name(statement: &Stmt) -> Option<&str> {
    match &statement.kind {
        StmtKind::Let { name, .. }
        | StmtKind::Function { name, .. }
        | StmtKind::Class { name, .. }
        | StmtKind::Protocol { name, .. } => Some(name),
        _ => None,
    }
}

struct TypeLinks {
    declarations: HashMap<String, String>,
}

impl TypeLinks {
    fn new(statements: &[Stmt]) -> Self {
        let declarations = statements
            .iter()
            .filter_map(|statement| match &statement.kind {
                StmtKind::Class { name, .. } if statement.public => {
                    Some((name.clone(), stable_anchor("类", name)))
                }
                StmtKind::Protocol { name, .. } if statement.public => {
                    Some((name.clone(), stable_anchor("协", name)))
                }
                _ => None,
            })
            .collect();
        Self { declarations }
    }

    fn render_optional(&self, type_ref: Option<&TypeRef>) -> String {
        type_ref.map_or_else(|| self.render_named("任意"), |ty| self.render(&ty.kind))
    }

    fn render(&self, kind: &TypeKind) -> String {
        match kind {
            TypeKind::Named(path) => self.render_named(&path.to_string()),
            TypeKind::Union(types) => types
                .iter()
                .map(|ty| self.render(ty))
                .collect::<Vec<_>>()
                .join(" | "),
            TypeKind::Nullable(ty) => format!("{} `?`", self.render(ty)),
            TypeKind::Generic { base, arguments } => format!(
                "{}`<`{} `>`",
                self.render_named(&base.to_string()),
                arguments
                    .iter()
                    .map(|argument| self.render(argument))
                    .collect::<Vec<_>>()
                    .join("，")
            ),
            TypeKind::Function { parameters, result } => format!(
                "{}（{}）→ {}",
                self.render_named("法"),
                parameters
                    .iter()
                    .map(|parameter| self.render(parameter))
                    .collect::<Vec<_>>()
                    .join("，"),
                self.render(result)
            ),
        }
    }

    fn render_named(&self, name: &str) -> String {
        if let Some(anchor) = self.declarations.get(name) {
            format!("[`{name}`](#{anchor})")
        } else if BUILTIN_TYPES.iter().any(|(builtin, _)| *builtin == name) {
            format!("[`{name}`](#类型-{})", anchor_text(name))
        } else {
            format!("`{name}`")
        }
    }
}

fn render_builtin_types(output: &mut String) {
    output.push_str("## 类型索引\n\n");
    for (name, description) in BUILTIN_TYPES {
        output.push_str(&format!(
            "<a id=\"类型-{}\"></a>\n\n- `{name}`：{description}\n",
            anchor_text(name)
        ));
    }
}

fn render_parameter_plain(parameter: &Parameter) -> String {
    format!(
        "{}{}",
        parameter.name,
        render_type_plain(parameter.type_ref.as_ref())
    )
}

fn render_type_plain(type_ref: Option<&TypeRef>) -> String {
    type_ref.map_or_else(String::new, |type_ref| format!("：{}", type_ref.name))
}

fn comment_before(span: &crate::source::Span) -> Option<String> {
    let lines = span.source.text.lines().collect::<Vec<_>>();
    let mut current = span.line.saturating_sub(1);
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

fn anchor_text(text: &str) -> String {
    let mut anchor = String::new();
    let mut dash = false;
    for character in text.chars() {
        if character.is_alphanumeric() || matches!(character, '_' | '-') || !character.is_ascii() {
            anchor.push(character.to_ascii_lowercase());
            dash = false;
        } else if !dash && !anchor.is_empty() {
            anchor.push('-');
            dash = true;
        }
    }
    anchor.trim_matches('-').to_owned()
}

fn visit(path: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in
        fs::read_dir(path).map_err(|error| format!("不能读取目录“{}”：{error}", path.display()))?
    {
        let path = entry.map_err(|error| error.to_string())?.path();
        if path.is_dir() {
            visit(&path, files)?;
        } else if path.extension().is_some_and(|extension| extension == "yx") {
            files.push(path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn includes_comments_type_links_module_index_and_stable_anchors() {
        let source = r#"
            /// 可相加之物。
            公 协 可加 则 法 相加（值：数）：数；终
            /// 加一并归还。
            公 法 加一（值：数）：数 则 归 值 加 1；终
            定 秘 为 1；
        "#;
        let output = markdown("算书", &crate::parse(source).unwrap());
        assert!(output.contains("## 模块索引"));
        assert!(output.contains("加一并归还"));
        assert!(output.contains("<a id=\"法-加一\"></a>"));
        assert!(output.contains("[`数`](#类型-数)"));
        assert!(!output.contains("`秘`"));
        assert_eq!(stable_anchor("法", "加一"), "法-加一");
    }

    #[test]
    fn links_binary_values_to_the_builtin_type_index() {
        let output = markdown(
            "二进制接口",
            &crate::parse("/// 原始响应。\n公 定 响应：字节串 为 空；").unwrap(),
        );
        assert!(output.contains("[`字节串`](#类型-字节串)"));
        assert!(output.contains("`字节串`：不可变的任意二进制数据"));
    }

    #[test]
    fn directory_generation_builds_a_module_index() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("yanxu-doc-{unique}"));
        fs::create_dir_all(root.join("子")).unwrap();
        fs::write(root.join("甲.yx"), "公 定 值：数 为 1；").unwrap();
        fs::write(root.join("子/乙.yx"), "公 法 答（）：文 则 归「善」；终").unwrap();
        let output = markdown_directory(&root).unwrap();
        assert!(output.contains("[`甲`](#模块-甲)"));
        assert!(output.contains("[`子/乙`](#模块-子-乙)"));
        fs::remove_dir_all(root).unwrap();
    }
}
