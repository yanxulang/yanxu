//! 言序 Language Server Protocol 实现。
//!
//! 服务以 UTF-16 LSP 坐标对外，语义功能共享 [`crate::semantic::SemanticIndex`]，
//! 包括补全、定义、引用、重命名、悬停和文档符号。

use crate::ast::{Stmt, StmtKind, TypePath, Visibility};
use crate::semantic::{SemanticIndex, Symbol, SymbolKind};
use crate::source::{SourceFile, Span};
use crate::token::TokenKind;
use crate::type_model::{ModuleId, TypeDeclarationKind, TypeId};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

const KEYWORDS: &[&str] = &[
    "令", "定", "置", "为", "言", "若", "则", "否则", "终", "当", "逐", "于", "异", "候", "法",
    "归", "类", "承", "父", "协", "纳", "域", "公", "私", "只", "静", "此", "引", "试", "救", "抛",
    "真", "假", "空", "是", "且", "或", "非",
];

const INTRINSICS: &[(&str, &str)] = &[
    ("时刻", "法（）：数"),
    ("长度", "法（任意）：数"),
    ("类型", "法（任意）：文"),
    ("追加", "法（列<任意>，任意）：列<任意>"),
    ("弹出", "法（列<任意>）：任意"),
    ("有键", "法（典<任意，任意>，任意）：理"),
    ("插入", "法（列<任意>，数，任意）：列<任意>"),
    ("删除", "法（列<任意>，数）：任意"),
    ("键列", "法（典<任意，任意>）：列<任意>"),
    ("值列", "法（典<任意，任意>）：列<任意>"),
    ("遍", "法（任意）：遍器"),
    ("续", "法（遍器）：元<理，任意>"),
    ("范围", "法（数，数）：遍器"),
    ("步进范围", "法（数，数，数）：遍器"),
    ("映射", "法（任意，法）：遍器"),
    ("筛选", "法（任意，法）：遍器"),
    ("折叠", "法（任意，任意，法）：任意"),
    ("排序", "法（任意）：列<任意>"),
    ("反转", "法（任意）：列<任意>"),
    ("包含", "法（任意，任意）：理"),
    ("寻找", "法（任意，法）：元<理，任意>"),
    ("取消", "法（任务<任意>）：理"),
    ("任务状态", "法（任务<任意>）：文"),
    ("并候", "法（列<任务<任意>>）：列<任意>"),
];

pub fn serve() -> io::Result<()> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    serve_io(stdin.lock(), stdout.lock())
}

fn serve_io<R: BufRead, W: Write>(mut reader: R, mut writer: W) -> io::Result<()> {
    let mut documents = HashMap::<String, String>::new();
    while let Some(message) = read_message(&mut reader)? {
        let method = message.get("method").and_then(Value::as_str).unwrap_or("");
        let id = message.get("id").cloned();
        match method {
            "initialize" => respond(&mut writer, id, initialize_result())?,
            "initialized" => {}
            "shutdown" => respond(&mut writer, id, Value::Null)?,
            "exit" => break,
            "textDocument/didOpen" => {
                if let Some(document) = message.pointer("/params/textDocument") {
                    let uri = document.get("uri").and_then(Value::as_str).unwrap_or("");
                    let text = document.get("text").and_then(Value::as_str).unwrap_or("");
                    documents.insert(uri.into(), text.into());
                    publish(&mut writer, uri, text)?;
                }
            }
            "textDocument/didChange" => {
                let uri = document_uri(&message);
                if let Some(text) = message
                    .pointer("/params/contentChanges/0/text")
                    .and_then(Value::as_str)
                {
                    documents.insert(uri.into(), text.into());
                    publish(&mut writer, uri, text)?;
                }
            }
            "textDocument/didClose" => {
                let uri = document_uri(&message);
                documents.remove(uri);
                publish_diagnostics(&mut writer, uri, &[])?;
            }
            "textDocument/formatting" => {
                let uri = document_uri(&message);
                let edits = documents.get(uri).and_then(|source| {
                    crate::parse_named(source, uri).ok().map(|statements| {
                        json!([{
                            "range": full_document_range(source),
                            "newText": crate::formatter::format(&statements)
                        }])
                    })
                });
                respond(&mut writer, id, edits.unwrap_or_else(|| json!([])))?;
            }
            "textDocument/completion"
            | "textDocument/definition"
            | "textDocument/references"
            | "textDocument/prepareRename"
            | "textDocument/rename"
            | "textDocument/hover"
            | "textDocument/documentSymbol" => {
                let uri = document_uri(&message);
                let result = documents.get(uri).map_or(Value::Null, |source| {
                    semantic_response(method, uri, source, &message)
                });
                respond(&mut writer, id, result)?;
            }
            _ if id.is_some() => respond_error(&mut writer, id, -32601, "方法尚未支持")?,
            _ => {}
        }
    }
    Ok(())
}

fn initialize_result() -> Value {
    json!({
        "capabilities": {
            "positionEncoding": "utf-16",
            "textDocumentSync": {"openClose": true, "change": 1},
            "documentFormattingProvider": true,
            "completionProvider": {"triggerCharacters": [".", "："]},
            "definitionProvider": true,
            "referencesProvider": true,
            "renameProvider": {"prepareProvider": true},
            "hoverProvider": true,
            "documentSymbolProvider": true
        },
        "serverInfo": {"name": "yanxu-lsp", "version": env!("CARGO_PKG_VERSION")}
    })
}

fn semantic_response(method: &str, uri: &str, source: &str, request: &Value) -> Value {
    let (line, utf16_column) = request_position(request);
    let column = character_column(source, line, utf16_column);
    let Ok(index) = SemanticIndex::build(source, uri) else {
        return if method == "textDocument/completion" {
            with_package_completions(
                completion_items(
                    None,
                    line,
                    column,
                    standard_module_at_completion(source, line, column).as_deref(),
                ),
                uri,
                source,
                line,
                column,
            )
        } else if method == "textDocument/documentSymbol" {
            json!([])
        } else {
            Value::Null
        };
    };
    match method {
        "textDocument/completion" => with_package_completions(
            completion_items(
                Some(&index),
                line,
                column,
                standard_module_at_completion(source, line, column).as_deref(),
            ),
            uri,
            source,
            line,
            column,
        ),
        "textDocument/definition" => qualified_definition(uri, source, line, column)
            .unwrap_or_else(|| definition(&index, uri, source, line, column)),
        "textDocument/references" => references(
            &index,
            uri,
            source,
            line,
            column,
            request
                .pointer("/params/context/includeDeclaration")
                .and_then(Value::as_bool)
                .unwrap_or(true),
        ),
        "textDocument/prepareRename" => {
            if qualified_external_symbol(uri, source, line, column) {
                Value::Null
            } else {
                prepare_rename(&index, source, line, column)
            }
        }
        "textDocument/rename" => {
            if qualified_external_symbol(uri, source, line, column) {
                Value::Null
            } else {
                rename(&index, uri, source, line, column, request)
            }
        }
        "textDocument/hover" => qualified_hover(uri, source, line, column)
            .unwrap_or_else(|| hover(&index, source, line, column)),
        "textDocument/documentSymbol" => document_symbols(&index, source),
        _ => Value::Null,
    }
}

fn with_package_completions(
    mut completion: Value,
    uri: &str,
    source: &str,
    line: usize,
    column: usize,
) -> Value {
    if let Some(items) = completion["items"].as_array_mut() {
        items.extend(package_completion_items(uri, source, line, column));
        items.extend(qualified_module_completion_items(uri, source, line, column));
        items.extend(package_member_completion_items(uri, source, line, column));
    }
    completion
}

fn package_member_completion_items(
    uri: &str,
    source: &str,
    line: usize,
    column: usize,
) -> Vec<Value> {
    let Some(alias) = module_alias_at_completion(source, line, column) else {
        return Vec::new();
    };
    let import_pattern =
        regex::Regex::new(r#"引\s*「包:([^」]+)」\s*为\s*([\p{L}_][\p{L}\p{N}_]*)"#)
            .expect("static package import regex");
    let Some(package_path) = import_pattern.captures_iter(source).find_map(|captures| {
        (captures.get(2)?.as_str() == alias).then(|| captures.get(1).unwrap().as_str().to_owned())
    }) else {
        return Vec::new();
    };
    let Some(path) = uri_file_path(uri) else {
        return Vec::new();
    };
    let Some(manifest) = crate::package::discover(&path).ok().flatten() else {
        return Vec::new();
    };
    // Language servers must never introduce network I/O while completing.
    let Ok(graph) = crate::package::resolve_graph(&manifest, true) else {
        return Vec::new();
    };
    let (dependency_alias, export_name) = package_path
        .split_once('/')
        .map_or((package_path.as_str(), "默认"), |(alias, export)| {
            (alias, export)
        });
    let Some(id) = graph.root_dependencies.get(dependency_alias) else {
        return Vec::new();
    };
    let Some(dependency) = graph.packages.get(id) else {
        return Vec::new();
    };
    let Some(export) = dependency.locked.exports.get(export_name) else {
        return Vec::new();
    };
    let module_path = dependency.root.join(export);
    let Ok(metadata) = std::fs::symlink_metadata(&module_path) else {
        return Vec::new();
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 8 * 1024 * 1024
    {
        return Vec::new();
    }
    let Ok(module_source) = std::fs::read_to_string(&module_path) else {
        return Vec::new();
    };
    let module_name = module_path.display().to_string();
    let Ok(tokens) = crate::lexer::scan_named(&module_source, &module_name) else {
        return Vec::new();
    };
    let Ok(statements) = crate::parser::parse(tokens) else {
        return Vec::new();
    };
    let public = statements
        .iter()
        .filter(|statement| statement.public)
        .filter_map(|statement| match &statement.kind {
            crate::ast::StmtKind::Let { name, .. }
            | crate::ast::StmtKind::Function { name, .. }
            | crate::ast::StmtKind::Class { name, .. }
            | crate::ast::StmtKind::Protocol { name, .. } => Some(name.as_str()),
            _ => None,
        })
        .collect::<std::collections::HashSet<_>>();
    let Ok(index) = SemanticIndex::build(&module_source, &module_name) else {
        return Vec::new();
    };
    index
        .symbols()
        .iter()
        .filter(|symbol| symbol.container.is_none() && public.contains(symbol.name.as_str()))
        .map(|symbol| {
            json!({
                "label": symbol.name,
                "kind": symbol.kind.completion_kind(),
                "detail": symbol.detail,
                "documentation": symbol.documentation.clone().unwrap_or_else(|| {
                    format!("包:{package_path}.{}", symbol.name)
                }),
                "sortText": format!("0-package-member-{}", symbol.name)
            })
        })
        .collect()
}

fn module_alias_at_completion(source: &str, line: usize, column: usize) -> Option<String> {
    let prefix = source
        .lines()
        .nth(line.saturating_sub(1))?
        .chars()
        .take(column.saturating_sub(1))
        .collect::<String>();
    let tokens = crate::lexer::scan(&prefix).ok()?;
    let mut kinds = tokens
        .iter()
        .map(|token| &token.kind)
        .filter(|kind| !matches!(kind, TokenKind::Eof))
        .rev();
    if !matches!(kinds.next(), Some(TokenKind::Dot)) {
        return None;
    }
    match kinds.next() {
        Some(TokenKind::Identifier(alias)) => Some(alias.clone()),
        _ => None,
    }
}

fn package_completion_items(uri: &str, source: &str, line: usize, column: usize) -> Vec<Value> {
    let prefix = source
        .lines()
        .nth(line.saturating_sub(1))
        .unwrap_or("")
        .chars()
        .take(column.saturating_sub(1))
        .collect::<String>();
    let Some(typed) = prefix
        .rsplit('「')
        .next()
        .and_then(|text| text.strip_prefix("包:"))
    else {
        return Vec::new();
    };
    let Some(path) = uri_file_path(uri) else {
        return Vec::new();
    };
    let Some(manifest) = crate::package::discover(&path).ok().flatten() else {
        return Vec::new();
    };
    let lock = crate::package::read_lock(manifest.root.join(crate::package::LOCK_NAME)).ok();
    let (requested_alias, export_prefix) = typed
        .split_once('/')
        .map_or((typed, None), |(alias, export)| (alias, Some(export)));
    if let Some(export_prefix) = export_prefix {
        let Some(lock) = lock else { return Vec::new() };
        let id = lock
            .root_dependencies
            .get(requested_alias)
            .or_else(|| lock.root_dev_dependencies.get(requested_alias));
        let Some(package) =
            id.and_then(|id| lock.packages.iter().find(|package| &package.id == id))
        else {
            return Vec::new();
        };
        return package
            .exports
            .keys()
            .filter(|name| name.starts_with(export_prefix))
            .map(|name| {
                json!({
                    "label": name,
                    "insertText": name,
                    "kind": 9,
                    "detail": format!("{} {} 的公开导出", package.name, package.version),
                    "documentation": format!("包:{requested_alias}/{name}"),
                    "sortText": format!("0-package-export-{name}")
                })
            })
            .collect();
    }
    manifest
        .dependencies
        .iter()
        .chain(manifest.dev_dependencies.iter())
        .filter(|(alias, _)| alias.starts_with(requested_alias))
        .map(|(alias, dependency)| {
            let locked = lock.as_ref().and_then(|lock| {
                lock.root_dependencies
                    .get(alias)
                    .or_else(|| lock.root_dev_dependencies.get(alias))
                    .and_then(|id| lock.packages.iter().find(|package| &package.id == id))
            });
            json!({
                "label": alias,
                "insertText": alias,
                "kind": 9,
                "detail": locked.map_or_else(
                    || dependency.to_string(),
                    |package| format!(
                        "{} {} · {}",
                        package.name,
                        package.version,
                        crate::package::safe_dependency_source_for_display(&package.source)
                    )
                ),
                "documentation": format!("包:{alias}；输入 / 可选择公开子模块"),
                "sortText": format!("0-package-{alias}")
            })
        })
        .collect()
}

fn uri_file_path(uri: &str) -> Option<std::path::PathBuf> {
    url::Url::parse(uri).ok()?.to_file_path().ok()
}

struct LspModuleGraph {
    root: ModuleId,
    modules: BTreeMap<ModuleId, LspModule>,
}

struct LspModule {
    uri: String,
    source: String,
    imports: BTreeMap<String, ModuleId>,
    exports: BTreeMap<String, LspExport>,
    local_types: BTreeMap<String, TypeId>,
}

struct LspExport {
    symbol: Symbol,
    statement: Stmt,
    module_id: ModuleId,
    type_id: Option<TypeId>,
    target_module: Option<ModuleId>,
}

struct QualifiedSelection {
    segments: Vec<String>,
    selected: usize,
    span: Span,
}

impl LspModuleGraph {
    fn build(uri: &str, source: &str) -> Result<Self, String> {
        let path = uri_file_path(uri).ok_or_else(|| "文档 URI 不是文件".to_owned())?;
        let canonical = fs::canonicalize(&path).unwrap_or(path);
        let root = ModuleId::for_path(&canonical);
        let mut graph = Self {
            root: root.clone(),
            modules: BTreeMap::new(),
        };
        let directory = canonical
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        graph.load_module(root, canonical, source.to_owned(), &directory)?;
        Ok(graph)
    }

    fn load_module(
        &mut self,
        module_id: ModuleId,
        path: PathBuf,
        source: String,
        directory: &Path,
    ) -> Result<(), String> {
        if self.modules.contains_key(&module_id) {
            return Ok(());
        }
        let parsed_source = lsp_parseable_source(&source);
        let source_name = path.display().to_string();
        let statements = crate::parse_named(&parsed_source, source_name.clone())
            .map_err(|error| error.to_string())?;
        let semantic = SemanticIndex::build(&parsed_source, &source_name)
            .map_err(|errors| format!("语义索引失败：{errors:?}"))?;
        let imports = statements
            .iter()
            .filter_map(|statement| match &statement.kind {
                StmtKind::Import { path, alias } => Some((
                    path.clone(),
                    alias.clone(),
                    statement.public,
                    statement.clone(),
                )),
                _ => None,
            })
            .collect::<Vec<_>>();
        let mut exports = BTreeMap::new();
        let mut local_types = BTreeMap::new();
        for statement in &statements {
            let (name, kind, declaration_kind) = match &statement.kind {
                StmtKind::Let { name, mutable, .. } => (
                    name,
                    if *mutable {
                        SymbolKind::Variable
                    } else {
                        SymbolKind::Constant
                    },
                    None,
                ),
                StmtKind::Function { name, .. } => (name, SymbolKind::Function, None),
                StmtKind::Class { name, .. } => {
                    (name, SymbolKind::Class, Some(TypeDeclarationKind::Class))
                }
                StmtKind::Protocol { name, .. } => (
                    name,
                    SymbolKind::Protocol,
                    Some(TypeDeclarationKind::Protocol),
                ),
                _ => continue,
            };
            let type_id =
                declaration_kind.map(|kind| TypeId::new(module_id.clone(), name.clone(), kind));
            if let Some(type_id) = &type_id {
                local_types.insert(name.clone(), type_id.clone());
            }
            if statement.public
                && let Some(symbol) = top_level_symbol(&semantic, name, kind)
            {
                exports.insert(
                    name.clone(),
                    LspExport {
                        symbol: symbol.clone(),
                        statement: statement.clone(),
                        module_id: module_id.clone(),
                        type_id,
                        target_module: None,
                    },
                );
            }
        }
        let uri = url::Url::from_file_path(&path)
            .map_err(|_| format!("不能把模块路径转换为 URI：{}", path.display()))?
            .to_string();
        self.modules.insert(
            module_id.clone(),
            LspModule {
                uri,
                source,
                imports: BTreeMap::new(),
                exports,
                local_types,
            },
        );
        for (requested, alias, public, statement) in imports {
            let target = self.load_import(&requested, directory)?;
            let module = self
                .modules
                .get_mut(&module_id)
                .expect("module inserted before imports are linked");
            module.imports.insert(alias.clone(), target.clone());
            if public && let Some(symbol) = top_level_symbol(&semantic, &alias, SymbolKind::Module)
            {
                module.exports.insert(
                    alias,
                    LspExport {
                        symbol: symbol.clone(),
                        statement,
                        module_id: module_id.clone(),
                        type_id: None,
                        target_module: Some(target),
                    },
                );
            }
        }
        Ok(())
    }

    fn load_import(&mut self, requested: &str, directory: &Path) -> Result<ModuleId, String> {
        if let Some(name) = requested.strip_prefix("标准:") {
            return Ok(ModuleId::standard(name));
        }
        let path = if let Some(name) = requested.strip_prefix("包:") {
            crate::package::resolve_dependency_scoped(None, directory, name)
                .map_err(|error| error.to_string())?
                .entry
        } else {
            let requested = Path::new(requested);
            if requested.is_absolute() {
                requested.to_path_buf()
            } else {
                directory.join(requested)
            }
        };
        let canonical = fs::canonicalize(&path)
            .map_err(|error| format!("不能读取 LSP 模块“{}”：{error}", path.display()))?;
        let module_id = ModuleId::for_path(&canonical);
        if self.modules.contains_key(&module_id) {
            return Ok(module_id);
        }
        let source = fs::read_to_string(&canonical)
            .map_err(|error| format!("不能读取 LSP 模块“{}”：{error}", canonical.display()))?;
        let child_directory = canonical.parent().unwrap_or(directory).to_path_buf();
        self.load_module(module_id.clone(), canonical, source, &child_directory)?;
        Ok(module_id)
    }

    fn resolve_module(&self, segments: &[String]) -> Option<&LspModule> {
        let root = self.modules.get(&self.root)?;
        let (alias, rest) = segments.split_first()?;
        let mut module_id = root.imports.get(alias)?;
        for segment in rest {
            let module = self.modules.get(module_id)?;
            module_id = module.exports.get(segment)?.target_module.as_ref()?;
        }
        self.modules.get(module_id)
    }

    fn resolve_export(&self, segments: &[String]) -> Option<&LspExport> {
        let (last, modules) = segments.split_last()?;
        let module = self.resolve_module(modules)?;
        module.exports.get(last)
    }

    fn resolve_type(&self, module_id: &ModuleId, path: &TypePath) -> Option<TypeId> {
        let names = path.names().map(str::to_owned).collect::<Vec<_>>();
        let module = self.modules.get(module_id)?;
        match names.as_slice() {
            [name] => module.local_types.get(name).cloned(),
            [alias, rest @ ..] => {
                let mut target = module.imports.get(alias)?;
                for segment in &rest[..rest.len().saturating_sub(1)] {
                    let module = self.modules.get(target)?;
                    target = module.exports.get(segment)?.target_module.as_ref()?;
                }
                let module = self.modules.get(target)?;
                module.exports.get(rest.last()?)?.type_id.clone()
            }
            [] => None,
        }
    }
}

fn lsp_parseable_source(source: &str) -> String {
    if crate::parse(source).is_ok() {
        return source.to_owned();
    }
    if source.trim_end().ends_with('.') {
        let mut completed = source.to_owned();
        completed.push_str("占位；");
        if crate::parse(&completed).is_ok() {
            return completed;
        }
        if let Some((prefix, _)) = source.rsplit_once('\n') {
            return format!("{prefix}\n");
        }
    }
    source.to_owned()
}

fn top_level_symbol<'a>(
    index: &'a SemanticIndex,
    name: &str,
    kind: SymbolKind,
) -> Option<&'a Symbol> {
    index
        .symbols()
        .iter()
        .find(|symbol| symbol.container.is_none() && symbol.name == name && symbol.kind == kind)
}

fn module_path_at_completion(
    source: &str,
    line: usize,
    column: usize,
) -> Option<(Vec<String>, bool)> {
    let prefix = source
        .lines()
        .nth(line.saturating_sub(1))?
        .chars()
        .take(column.saturating_sub(1))
        .collect::<String>();
    let tokens = crate::lexer::scan(&prefix).ok()?;
    let tokens = tokens
        .iter()
        .filter(|token| !matches!(token.kind, TokenKind::Eof))
        .collect::<Vec<_>>();
    if !matches!(tokens.last().map(|token| &token.kind), Some(TokenKind::Dot)) {
        return None;
    }
    let mut cursor = tokens.len().checked_sub(2)?;
    let mut segments = Vec::new();
    loop {
        let TokenKind::Identifier(name) = &tokens.get(cursor)?.kind else {
            return None;
        };
        segments.push(name.clone());
        if cursor < 2 || !matches!(tokens[cursor - 1].kind, TokenKind::Dot) {
            break;
        }
        cursor -= 2;
    }
    segments.reverse();
    let type_context = tokens.get(cursor.wrapping_sub(1)).is_some_and(|token| {
        matches!(
            token.kind,
            TokenKind::Colon
                | TokenKind::Inherit
                | TokenKind::Implements
                | TokenKind::Is
                | TokenKind::Less
                | TokenKind::Pipe
                | TokenKind::Comma
        )
    });
    Some((segments, type_context))
}

fn qualified_module_completion_items(
    uri: &str,
    source: &str,
    line: usize,
    column: usize,
) -> Vec<Value> {
    let Some((segments, type_context)) = module_path_at_completion(source, line, column) else {
        return Vec::new();
    };
    let Ok(graph) = LspModuleGraph::build(uri, source) else {
        return Vec::new();
    };
    let Some(module) = graph.resolve_module(&segments) else {
        return Vec::new();
    };
    module
        .exports
        .values()
        .map(|export| {
            let type_priority = matches!(export.symbol.kind, SymbolKind::Class | SymbolKind::Protocol);
            let canonical = export.type_id.as_ref().map(TypeId::qualified_name);
            json!({
                "label": export.symbol.name,
                "kind": export.symbol.kind.completion_kind(),
                "detail": export.symbol.detail,
                "documentation": canonical.unwrap_or_else(|| {
                    export.symbol.documentation.clone().unwrap_or_else(|| module.uri.clone())
                }),
                "sortText": if type_context {
                    format!("{}-qualified-{}", if type_priority { 0 } else { 1 }, export.symbol.name)
                } else {
                    format!("0-qualified-{}", export.symbol.name)
                }
            })
        })
        .collect()
}

fn qualified_path_at(
    uri: &str,
    source: &str,
    line: usize,
    column: usize,
) -> Option<QualifiedSelection> {
    let tokens = crate::lexer::scan_named(source, uri).ok()?;
    let selected = tokens.iter().position(|token| {
        matches!(token.kind, TokenKind::Identifier(_))
            && token.span.line == line
            && column >= token.span.column
            && column <= token.span.end_column
    })?;
    let mut start = selected;
    while start >= 2
        && matches!(tokens[start - 1].kind, TokenKind::Dot)
        && matches!(tokens[start - 2].kind, TokenKind::Identifier(_))
    {
        start -= 2;
    }
    let mut end = selected;
    while end + 2 < tokens.len()
        && matches!(tokens[end + 1].kind, TokenKind::Dot)
        && matches!(tokens[end + 2].kind, TokenKind::Identifier(_))
    {
        end += 2;
    }
    if start == end {
        return None;
    }
    let segments = (start..=end)
        .step_by(2)
        .map(|index| match &tokens[index].kind {
            TokenKind::Identifier(name) => name.clone(),
            _ => unreachable!("qualified path contains identifier positions"),
        })
        .collect::<Vec<_>>();
    Some(QualifiedSelection {
        segments,
        selected: (selected - start) / 2,
        span: tokens[selected].span.clone(),
    })
}

fn qualified_definition(uri: &str, source: &str, line: usize, column: usize) -> Option<Value> {
    let selection = qualified_path_at(uri, source, line, column)?;
    if selection.selected == 0 {
        return None;
    }
    let graph = LspModuleGraph::build(uri, source).ok()?;
    let export = graph.resolve_export(&selection.segments[..=selection.selected])?;
    let module = graph.modules.get(&export.module_id)?;
    Some(json!({
        "uri": module.uri,
        "range": range(&export.symbol.selection, &module.source)
    }))
}

fn qualified_external_symbol(uri: &str, source: &str, line: usize, column: usize) -> bool {
    let Some(selection) = qualified_path_at(uri, source, line, column) else {
        return false;
    };
    selection.selected > 0
        && LspModuleGraph::build(uri, source)
            .ok()
            .and_then(|graph| {
                graph
                    .resolve_export(&selection.segments[..=selection.selected])
                    .map(|_| ())
            })
            .is_some()
}

fn qualified_hover(uri: &str, source: &str, line: usize, column: usize) -> Option<Value> {
    let selection = qualified_path_at(uri, source, line, column)?;
    if selection.selected == 0 {
        return None;
    }
    let graph = LspModuleGraph::build(uri, source).ok()?;
    let export = graph.resolve_export(&selection.segments[..=selection.selected])?;
    let markdown = qualified_hover_markdown(&graph, export);
    Some(json!({
        "contents": {"kind": "markdown", "value": markdown},
        "range": range(&selection.span, source)
    }))
}

fn qualified_hover_markdown(graph: &LspModuleGraph, export: &LspExport) -> String {
    let mut markdown = format!("```yanxu\n{}\n```", export.symbol.detail);
    if let Some(type_id) = &export.type_id {
        markdown.push_str(&format!(
            "\n\n- 声明种类：{}\n- 完整限定名称：`{}`\n- 所属模块：`{}`",
            type_id.kind,
            type_id.qualified_name(),
            type_id.module
        ));
    } else if let Some(target) = &export.target_module {
        markdown.push_str(&format!("\n\n- 声明种类：模块\n- 原始模块：`{target}`"));
    }
    match &export.statement.kind {
        StmtKind::Class {
            superclass,
            protocols,
            fields,
            methods,
            ..
        } => {
            if let Some(superclass) = superclass {
                let resolved = graph
                    .resolve_type(&export.module_id, superclass)
                    .map_or_else(
                        || superclass.to_string(),
                        |type_id| type_id.qualified_name(),
                    );
                markdown.push_str(&format!("\n- 父类：`{resolved}`"));
            }
            if !protocols.is_empty() {
                let protocols = protocols
                    .iter()
                    .map(|protocol| {
                        graph.resolve_type(&export.module_id, protocol).map_or_else(
                            || protocol.to_string(),
                            |type_id| type_id.qualified_name(),
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("，");
                markdown.push_str(&format!("\n- 协议：`{protocols}`"));
            }
            let members = fields
                .iter()
                .filter(|field| field.visibility == Visibility::Public)
                .map(|field| format!("{}：{}", field.name, field.type_ref.name))
                .chain(methods.iter().filter_map(|method| match &method.kind {
                    StmtKind::Function { name, .. }
                        if method.member_visibility == Visibility::Public =>
                    {
                        Some(format!("{name}（法）"))
                    }
                    _ => None,
                }))
                .collect::<Vec<_>>();
            if !members.is_empty() {
                markdown.push_str(&format!("\n- 公开成员：{}", members.join("，")));
            }
        }
        StmtKind::Protocol {
            fields, methods, ..
        } => {
            let members = fields
                .iter()
                .map(|field| format!("{}：{}", field.name, field.type_ref.name))
                .chain(methods.iter().filter_map(|method| match &method.kind {
                    StmtKind::Function { name, .. } => Some(format!("{name}（法）")),
                    _ => None,
                }))
                .collect::<Vec<_>>();
            if !members.is_empty() {
                markdown.push_str(&format!("\n- 必需成员：{}", members.join("，")));
            }
        }
        _ => {}
    }
    if let Some(documentation) = &export.symbol.documentation {
        markdown.push_str("\n\n");
        markdown.push_str(documentation);
    }
    markdown
}

fn completion_items(
    index: Option<&SemanticIndex>,
    line: usize,
    column: usize,
    standard_module: Option<&str>,
) -> Value {
    let mut items = Vec::new();
    if let Some(index) = index {
        for symbol in index.visible_symbols(line, column) {
            items.push(json!({
                "label": symbol.name,
                "kind": symbol.kind.completion_kind(),
                "detail": symbol.detail,
                "documentation": symbol.documentation,
                "sortText": format!("0-{}", symbol.name)
            }));
        }
    }
    for (name, signature) in INTRINSICS {
        items.push(json!({
            "label": name,
            "kind": 3,
            "detail": signature,
            "sortText": format!("1-{name}")
        }));
    }
    if let Some(module_name) = standard_module
        && let Ok(manifest) = crate::stdlib::api_manifest()
        && let Some(module) = manifest["modules"]
            .as_array()
            .and_then(|modules| modules.iter().find(|module| module["name"] == module_name))
        && let Some(members) = module["members"].as_array()
    {
        for member in members {
            let Some(name) = member["name"].as_str() else {
                continue;
            };
            items.push(json!({
                "label": name,
                "kind": if member["kind"] == "constant" { 21 } else { 3 },
                "detail": member["signature"].as_str().unwrap_or("标准库成员"),
                "documentation": format!("标准:{module_name}.{name}"),
                "sortText": format!("0-stdlib-{name}")
            }));
        }
    }
    for keyword in KEYWORDS {
        items.push(json!({
            "label": keyword,
            "kind": 14,
            "detail": "言序关键字",
            "sortText": format!("2-{keyword}")
        }));
    }
    json!({"isIncomplete": false, "items": items})
}

fn standard_module_at_completion(source: &str, line: usize, column: usize) -> Option<String> {
    let prefix = source
        .lines()
        .nth(line.saturating_sub(1))?
        .chars()
        .take(column.saturating_sub(1))
        .collect::<String>();
    let tokens = crate::lexer::scan(&prefix).ok()?;
    let mut kinds = tokens
        .iter()
        .map(|token| &token.kind)
        .filter(|kind| !matches!(kind, TokenKind::Eof))
        .rev();
    if !matches!(kinds.next(), Some(TokenKind::Dot)) {
        return None;
    }
    let Some(TokenKind::Identifier(alias)) = kinds.next() else {
        return None;
    };
    let tokens = crate::lexer::scan(source).ok()?;
    tokens.windows(4).find_map(|tokens| match tokens {
        [
            crate::token::Token {
                kind: TokenKind::Import,
                ..
            },
            crate::token::Token {
                kind: TokenKind::String(path),
                ..
            },
            crate::token::Token {
                kind: TokenKind::Be,
                ..
            },
            crate::token::Token {
                kind: TokenKind::Identifier(candidate),
                ..
            },
        ] if candidate == alias => path.strip_prefix("标准:").map(str::to_owned),
        _ => None,
    })
}

fn definition(index: &SemanticIndex, uri: &str, source: &str, line: usize, column: usize) -> Value {
    index.symbol_at(line, column).map_or(
        Value::Null,
        |symbol| json!({"uri": uri, "range": range(&symbol.selection, source)}),
    )
}

fn references(
    index: &SemanticIndex,
    uri: &str,
    source: &str,
    line: usize,
    column: usize,
    include_declaration: bool,
) -> Value {
    index.symbol_at(line, column).map_or_else(
        || json!([]),
        |symbol| {
            Value::Array(
                index
                    .references(symbol.id, include_declaration)
                    .into_iter()
                    .map(|occurrence| json!({"uri": uri, "range": range(&occurrence.span, source)}))
                    .collect(),
            )
        },
    )
}

fn prepare_rename(index: &SemanticIndex, source: &str, line: usize, column: usize) -> Value {
    index.symbol_at(line, column).map_or(
        Value::Null,
        |symbol| json!({"range": range(&symbol.selection, source), "placeholder": symbol.name}),
    )
}

fn rename(
    index: &SemanticIndex,
    uri: &str,
    source: &str,
    line: usize,
    column: usize,
    request: &Value,
) -> Value {
    let Some(new_name) = request
        .pointer("/params/newName")
        .and_then(Value::as_str)
        .filter(|name| valid_identifier(name))
    else {
        return Value::Null;
    };
    index.symbol_at(line, column).map_or(Value::Null, |symbol| {
        let edits = index
            .references(symbol.id, true)
            .into_iter()
            .map(
                |occurrence| json!({"range": range(&occurrence.span, source), "newText": new_name}),
            )
            .collect::<Vec<_>>();
        json!({"changes": {uri: edits}})
    })
}

fn hover(index: &SemanticIndex, source: &str, line: usize, column: usize) -> Value {
    index.symbol_at(line, column).map_or(Value::Null, |symbol| {
        let mut markdown = format!("```yanxu\n{}\n```", symbol.detail);
        if let Some(documentation) = &symbol.documentation {
            markdown.push_str("\n\n");
            markdown.push_str(documentation);
        }
        json!({
            "contents": {"kind": "markdown", "value": markdown},
            "range": range(&symbol.selection, source)
        })
    })
}

fn document_symbols(index: &SemanticIndex, source: &str) -> Value {
    let top_level = index
        .symbols()
        .iter()
        .filter(|symbol| symbol.container.is_none() && symbol.kind != SymbolKind::Parameter)
        .map(|symbol| {
            let children = index
                .symbols()
                .iter()
                .filter(|child| {
                    child.container.as_deref() == Some(&symbol.name)
                        && matches!(child.kind, SymbolKind::Method | SymbolKind::Field)
                })
                .map(|child| document_symbol(child, source, None))
                .collect::<Vec<_>>();
            document_symbol(symbol, source, (!children.is_empty()).then_some(children))
        })
        .collect::<Vec<_>>();
    Value::Array(top_level)
}

fn document_symbol(symbol: &Symbol, source: &str, children: Option<Vec<Value>>) -> Value {
    let mut value = json!({
        "name": symbol.name,
        "detail": symbol.detail,
        "kind": symbol.kind.lsp_kind(),
        "range": range(&symbol.declaration, source),
        "selectionRange": range(&symbol.selection, source)
    });
    if let Some(children) = children {
        value["children"] = Value::Array(children);
    }
    value
}

pub fn diagnostics(source: &str, name: &str) -> Vec<Value> {
    let statements = match crate::lexer::scan_named(source, name) {
        Err(error) => return vec![diagnostic(&error.span, source, &error.message, 1)],
        Ok(tokens) => match crate::parser::parse(tokens) {
            Err(error) => return vec![diagnostic(&error.span, source, &error.message, 1)],
            Ok(statements) => statements,
        },
    };
    if let Err(error) = crate::resolver::resolve(&statements) {
        return vec![diagnostic(&error.span, source, &error.message, 1)];
    }
    let mut diagnostics = crate::type_checker::check(&statements)
        .err()
        .unwrap_or_default()
        .into_iter()
        .map(|error| diagnostic(&error.span, source, &error.message, 1))
        .collect::<Vec<_>>();
    if let Some(path) = uri_file_path(name)
        && let Ok(Some(manifest)) = crate::package::discover(&path)
    {
        if let Err(error) = crate::package::validate_lock(&manifest) {
            let span = Span::new(SourceFile::new(name, source), 1, 1, 1, 1);
            diagnostics.push(diagnostic(&span, source, &error.to_string(), 2));
        }
        if let Ok(tokens) = crate::lexer::scan_named(source, name) {
            for pair in tokens.windows(2) {
                if matches!(pair[0].kind, TokenKind::Import)
                    && let TokenKind::String(import) = &pair[1].kind
                    && let Some(package) = import.strip_prefix("包:")
                {
                    let alias = package.split('/').next().unwrap_or(package);
                    if !manifest.dependencies.contains_key(alias)
                        && !manifest.dev_dependencies.contains_key(alias)
                    {
                        diagnostics.push(diagnostic(
                            &pair[1].span,
                            source,
                            &format!("未声明包依赖别名“{alias}”；请先执行 yanbao add {alias}"),
                            1,
                        ));
                    }
                }
            }
        }
    }
    diagnostics
}

fn diagnostic(span: &Span, source: &str, message: &str, severity: u8) -> Value {
    json!({
        "range": range(span, source),
        "severity": severity,
        "source": "言序",
        "message": message
    })
}

fn range(span: &Span, source: &str) -> Value {
    json!({
        "start": {
            "line": span.line.saturating_sub(1),
            "character": utf16_column(source, span.line, span.column)
        },
        "end": {
            "line": span.end_line.saturating_sub(1),
            "character": utf16_column(source, span.end_line, span.end_column)
        }
    })
}

fn full_document_range(source: &str) -> Value {
    let line_count = source.lines().count().max(1);
    let last_line = source.lines().last().unwrap_or("");
    json!({
        "start": {"line": 0, "character": 0},
        "end": {"line": line_count - 1, "character": last_line.encode_utf16().count()}
    })
}

fn utf16_column(source: &str, line: usize, character_column: usize) -> usize {
    source
        .lines()
        .nth(line.saturating_sub(1))
        .unwrap_or("")
        .chars()
        .take(character_column.saturating_sub(1))
        .map(char::len_utf16)
        .sum()
}

fn character_column(source: &str, line: usize, utf16_column: usize) -> usize {
    let mut units = 0;
    let mut characters = 0;
    for character in source
        .lines()
        .nth(line.saturating_sub(1))
        .unwrap_or("")
        .chars()
    {
        if units >= utf16_column {
            break;
        }
        units += character.len_utf16();
        characters += 1;
    }
    characters + 1
}

fn request_position(request: &Value) -> (usize, usize) {
    (
        request
            .pointer("/params/position/line")
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize
            + 1,
        request
            .pointer("/params/position/character")
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize,
    )
}

fn valid_identifier(name: &str) -> bool {
    let Ok(tokens) = crate::lexer::scan(name) else {
        return false;
    };
    matches!(
        tokens.as_slice(),
        [
            crate::token::Token {
                kind: TokenKind::Identifier(value),
                ..
            },
            crate::token::Token {
                kind: TokenKind::Eof,
                ..
            }
        ] if value == name
    )
}

fn document_uri(message: &Value) -> &str {
    message
        .pointer("/params/textDocument/uri")
        .and_then(Value::as_str)
        .unwrap_or("")
}

fn publish(writer: &mut impl Write, uri: &str, source: &str) -> io::Result<()> {
    publish_diagnostics(writer, uri, &diagnostics(source, uri))
}

fn publish_diagnostics(
    writer: &mut impl Write,
    uri: &str,
    diagnostics: &[Value],
) -> io::Result<()> {
    send(
        writer,
        &json!({
            "jsonrpc": "2.0",
            "method": "textDocument/publishDiagnostics",
            "params": {"uri": uri, "diagnostics": diagnostics}
        }),
    )
}

fn respond(writer: &mut impl Write, id: Option<Value>, result: Value) -> io::Result<()> {
    send(
        writer,
        &json!({"jsonrpc": "2.0", "id": id.unwrap_or(Value::Null), "result": result}),
    )
}

fn respond_error(
    writer: &mut impl Write,
    id: Option<Value>,
    code: i32,
    message: &str,
) -> io::Result<()> {
    send(
        writer,
        &json!({
            "jsonrpc": "2.0",
            "id": id.unwrap_or(Value::Null),
            "error": {"code": code, "message": message}
        }),
    )
}

fn send(writer: &mut impl Write, value: &Value) -> io::Result<()> {
    let body = serde_json::to_vec(value).map_err(io::Error::other)?;
    write!(writer, "Content-Length: {}\r\n\r\n", body.len())?;
    writer.write_all(&body)?;
    writer.flush()
}

fn read_message(reader: &mut impl BufRead) -> io::Result<Option<Value>> {
    let mut length = None;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header)? == 0 {
            return Ok(None);
        }
        if header == "\r\n" || header == "\n" {
            break;
        }
        if let Some(value) = header
            .strip_prefix("Content-Length:")
            .and_then(|value| value.trim().parse::<usize>().ok())
        {
            length = Some(value);
        }
    }
    let length =
        length.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "缺少 Content-Length"))?;
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    serde_json::from_slice(&body)
        .map(Some)
        .map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(method: &str, line: usize, character: usize) -> Value {
        json!({
            "method": method,
            "params": {
                "textDocument": {"uri": "file:///语义.yx"},
                "position": {"line": line, "character": character},
                "context": {"includeDeclaration": true},
                "newName": "相加"
            }
        })
    }

    fn request_for(
        uri: &str,
        method: &str,
        line: usize,
        character: usize,
        new_name: &str,
    ) -> Value {
        json!({
            "method": method,
            "params": {
                "textDocument": {"uri": uri},
                "position": {"line": line, "character": character},
                "context": {"includeDeclaration": true},
                "newName": new_name
            }
        })
    }

    fn last_position(source: &str, text: &str, inner_offset: usize) -> (usize, usize) {
        let byte = source.rfind(text).expect("test text exists");
        let prefix = &source[..byte];
        let line = prefix.bytes().filter(|byte| *byte == b'\n').count();
        let line_prefix = prefix.rsplit_once('\n').map_or(prefix, |(_, line)| line);
        let character = line_prefix.encode_utf16().count()
            + text
                .chars()
                .take(inner_offset)
                .collect::<String>()
                .encode_utf16()
                .count();
        (line, character)
    }

    #[test]
    fn exposes_static_diagnostics_in_utf16_coordinates() {
        let items = diagnostics("定 😀 = 1；", "file:///bad.yx");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["range"]["start"]["character"], 5);
        assert!(items[0]["message"].as_str().unwrap().contains("赋值请用"));
    }

    #[test]
    fn supports_all_semantic_language_features() {
        let source =
            "/// 两数相加。\n法 求和（甲：数，乙：数）：数 则 归 甲 加 乙；终\n言 求和（1，2）；";
        let uri = "file:///语义.yx";

        let completion = semantic_response(
            "textDocument/completion",
            uri,
            source,
            &request("textDocument/completion", 2, 2),
        );
        assert!(
            completion["items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item["label"] == "求和"
                    && item["detail"].as_str().unwrap().contains("数"))
        );
        for keyword in ["父", "是"] {
            assert!(
                completion["items"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|item| item["label"] == keyword && item["kind"] == 14)
            );
        }

        let definition = semantic_response(
            "textDocument/definition",
            uri,
            source,
            &request("textDocument/definition", 2, 3),
        );
        assert_eq!(definition["range"]["start"]["line"], 1);

        let references = semantic_response(
            "textDocument/references",
            uri,
            source,
            &request("textDocument/references", 2, 3),
        );
        assert_eq!(references.as_array().unwrap().len(), 2);

        let renamed = semantic_response(
            "textDocument/rename",
            uri,
            source,
            &request("textDocument/rename", 2, 3),
        );
        assert_eq!(renamed["changes"][uri].as_array().unwrap().len(), 2);

        let hover = semantic_response(
            "textDocument/hover",
            uri,
            source,
            &request("textDocument/hover", 2, 3),
        );
        assert!(
            hover["contents"]["value"]
                .as_str()
                .unwrap()
                .contains("两数相加")
        );

        let symbols = semantic_response(
            "textDocument/documentSymbol",
            uri,
            source,
            &request("textDocument/documentSymbol", 0, 0),
        );
        assert_eq!(symbols[0]["name"], "求和");
    }

    #[test]
    fn completes_versioned_binary_standard_library_members() {
        let source = "引「标准:字节」为 字节；\n字节.";
        assert_eq!(
            standard_module_at_completion(source, 2, 4).as_deref(),
            Some("字节")
        );
        let completion = semantic_response(
            "textDocument/completion",
            "file:///字节.yx",
            source,
            &request("textDocument/completion", 1, 3),
        );
        let items = completion["items"].as_array().unwrap();
        for member in ["从文字", "转文字", "切片", "从数列"] {
            assert!(
                items.iter().any(|item| {
                    item["label"] == member
                        && item["documentation"]
                            .as_str()
                            .is_some_and(|detail| detail.starts_with("标准:字节."))
                }),
                "缺少字节标准库补全：{member}"
            );
        }
    }

    #[test]
    fn announces_semantic_capabilities() {
        let capabilities = initialize_result()["capabilities"].clone();
        assert_eq!(capabilities["definitionProvider"], true);
        assert_eq!(capabilities["renameProvider"]["prepareProvider"], true);
        assert_eq!(capabilities["positionEncoding"], "utf-16");
    }

    #[test]
    fn completes_locked_package_aliases_exports_and_reports_package_drift() {
        let root = std::env::temp_dir().join(format!(
            "yanxu-lsp-package-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let app = root.join("app");
        let dependency = root.join("dependency");
        std::fs::create_dir_all(app.join("src")).unwrap();
        std::fs::create_dir_all(dependency.join("src")).unwrap();
        std::fs::write(
            dependency.join(crate::package::MANIFEST_NAME),
            "[包]\n格式=2\n名称='工具包'\n版本='1.2.0'\n入口='src/主.yx'\n[导出]\n默认='src/主.yx'\n配置='src/配置.yx'\n",
        )
        .unwrap();
        std::fs::write(dependency.join("src/主.yx"), "公 定 值 为 1；").unwrap();
        std::fs::write(dependency.join("src/配置.yx"), "公 定 名 为「配置」；").unwrap();
        std::fs::write(
            app.join(crate::package::MANIFEST_NAME),
            "[包]\n格式=2\n名称='应用'\n版本='1.0.0'\n入口='src/主.yx'\n[依赖]\n工具别名={包='工具包',路径='../dependency'}\n",
        )
        .unwrap();
        let entry = app.join("src/主.yx");
        std::fs::write(&entry, "").unwrap();
        let manifest = crate::package::load(app.join(crate::package::MANIFEST_NAME)).unwrap();
        crate::package::ensure_lock(&manifest, false).unwrap();
        let uri = url::Url::from_file_path(&entry).unwrap().to_string();

        let alias_source = "引「包:工";
        let aliases =
            package_completion_items(&uri, alias_source, 1, alias_source.chars().count() + 1);
        assert!(aliases.iter().any(|item| {
            item["label"] == "工具别名" && item["detail"].as_str().unwrap().contains("1.2.0")
        }));
        let export_source = "引「包:工具别名/配";
        let exports =
            package_completion_items(&uri, export_source, 1, export_source.chars().count() + 1);
        assert!(exports.iter().any(|item| item["label"] == "配置"));

        let member_source = "引「包:工具别名」为 工具；\n工具.";
        let members =
            package_member_completion_items(&uri, member_source, 2, "工具.".chars().count() + 1);
        assert!(members.iter().any(|item| {
            item["label"] == "值"
                && item["documentation"]
                    .as_str()
                    .is_some_and(|documentation| documentation.contains("包:工具别名"))
        }));

        let source = "引「包:未声明」为 未知；";
        std::fs::write(
            app.join(crate::package::MANIFEST_NAME),
            std::fs::read_to_string(app.join(crate::package::MANIFEST_NAME)).unwrap() + "\n",
        )
        .unwrap();
        let findings = diagnostics(source, &uri);
        assert!(
            findings
                .iter()
                .any(|item| item["message"].as_str().unwrap().contains("未声明包依赖"))
        );
        assert!(findings.iter().any(|item| {
            item["message"]
                .as_str()
                .unwrap()
                .contains("锁文件与清单不一致")
        }));
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn package_completion_and_diagnostics_redact_unsafe_lock_sources() {
        let root = std::env::temp_dir().join(format!(
            "yanxu-lsp-lock-source-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let app = root.join("app");
        let dependency = root.join("dependency");
        std::fs::create_dir_all(app.join("src")).unwrap();
        std::fs::create_dir_all(&dependency).unwrap();
        std::fs::write(
            dependency.join(crate::package::MANIFEST_NAME),
            "[包]\n格式=2\n名称='依赖包'\n版本='1.0.0'\n入口='main.yx'\n",
        )
        .unwrap();
        std::fs::write(dependency.join("main.yx"), "公 定 值 为 1；").unwrap();
        std::fs::write(
            app.join(crate::package::MANIFEST_NAME),
            "[包]\n格式=2\n名称='应用'\n版本='1.0.0'\n入口='src/主.yx'\n[依赖]\n依赖={包='依赖包',路径='../dependency'}\n",
        )
        .unwrap();
        let entry = app.join("src/主.yx");
        std::fs::write(&entry, "言 1；").unwrap();
        let manifest = crate::package::load(app.join(crate::package::MANIFEST_NAME)).unwrap();
        crate::package::ensure_lock(&manifest, false).unwrap();

        let lock_path = app.join(crate::package::LOCK_NAME);
        let mut lock = crate::package::read_lock(&lock_path).unwrap();
        let marker = "lsp-lock-value-must-not-appear";
        lock.packages[0].source = format!("path:https://user:{marker}@example.invalid/package.git");
        lock.packages[0].revision = Some(format!("user:{marker}@example.invalid"));
        std::fs::write(&lock_path, toml::to_string_pretty(&lock).unwrap()).unwrap();

        let uri = url::Url::from_file_path(&entry).unwrap().to_string();
        let source = "引「包:依";
        let items = package_completion_items(&uri, source, 1, source.chars().count() + 1);
        let completion_text = serde_json::to_string(&items).unwrap();
        assert!(!completion_text.contains(marker), "{completion_text}");

        let diagnostic_text = serde_json::to_string(&diagnostics("言 1；", &uri)).unwrap();
        assert!(!diagnostic_text.contains(marker), "{diagnostic_text}");
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn qualified_modules_complete_hover_define_and_rename_without_name_collisions() {
        let root = std::env::temp_dir().join(format!(
            "yanxu-lsp-qualified-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("child.yx"), "公 定 子值：数 为 1；\n").unwrap();
        std::fs::write(
            root.join("base.yx"),
            "公 引「child.yx」为 子模块；\n公 协 可描述 则 法 描述（）：文；终\n公 类 视图 纳 可描述 则 公 域 名称：文；公 法 描述（）：文 则 归 此.名称；终 终\n公 法 建立（）：视图 则 归 视图（）；终\n公 定 版本：文 为「1」；\n",
        )
        .unwrap();
        std::fs::write(
            root.join("controls.yx"),
            "引「base.yx」为 基础；\n公 类 按钮 承 基础.视图 纳 基础.可描述 则 公 法 描述（）：文 则 归「按钮」；终 终\n",
        )
        .unwrap();
        std::fs::write(root.join("facade.yx"), "公 引「controls.yx」为 控件；\n").unwrap();
        std::fs::write(root.join("a.yx"), "公 类 节点 则 终\n").unwrap();
        std::fs::write(root.join("b.yx"), "公 类 节点 则 终\n").unwrap();

        let main_path = root.join("main.yx");
        let main_uri = url::Url::from_file_path(&main_path).unwrap().to_string();
        let canonical_uri = |path: PathBuf| {
            url::Url::from_file_path(std::fs::canonicalize(path).unwrap())
                .unwrap()
                .to_string()
        };
        let completion_source = "引「base.yx」为 基础；\n基础.";
        std::fs::write(&main_path, completion_source).unwrap();
        let completion = semantic_response(
            "textDocument/completion",
            &main_uri,
            completion_source,
            &request_for(
                &main_uri,
                "textDocument/completion",
                1,
                "基础.".encode_utf16().count(),
                "未用",
            ),
        );
        let items = completion["items"].as_array().unwrap();
        for (name, kind) in [
            ("视图", 7),
            ("可描述", 8),
            ("子模块", 9),
            ("建立", 3),
            ("版本", 21),
        ] {
            assert!(
                items
                    .iter()
                    .any(|item| item["label"] == name && item["kind"] == kind),
                "缺少 {name}：{completion}"
            );
        }

        let type_completion_source = "引「base.yx」为 基础；\n定 值：基础.";
        std::fs::write(&main_path, type_completion_source).unwrap();
        let type_completion = semantic_response(
            "textDocument/completion",
            &main_uri,
            type_completion_source,
            &request_for(
                &main_uri,
                "textDocument/completion",
                1,
                "定 值：基础.".encode_utf16().count(),
                "未用",
            ),
        );
        let type_items = type_completion["items"].as_array().unwrap();
        let view = type_items
            .iter()
            .find(|item| item["label"] == "视图")
            .unwrap();
        let function = type_items
            .iter()
            .find(|item| item["label"] == "建立")
            .unwrap();
        assert!(
            view["sortText"]
                .as_str()
                .unwrap()
                .starts_with("0-qualified")
        );
        assert!(
            function["sortText"]
                .as_str()
                .unwrap()
                .starts_with("1-qualified")
        );

        let semantic_source = "引「base.yx」为 基础；\n定 根：基础.视图 为 基础.视图（）；\n";
        std::fs::write(&main_path, semantic_source).unwrap();
        let (line, character) = last_position(semantic_source, "基础.视图", 3);
        let definition = semantic_response(
            "textDocument/definition",
            &main_uri,
            semantic_source,
            &request_for(
                &main_uri,
                "textDocument/definition",
                line,
                character,
                "未用",
            ),
        );
        assert_eq!(definition["uri"], canonical_uri(root.join("base.yx")));
        assert_eq!(definition["range"]["start"]["line"], 2);
        let hover = semantic_response(
            "textDocument/hover",
            &main_uri,
            semantic_source,
            &request_for(&main_uri, "textDocument/hover", line, character, "未用"),
        );
        let hover_text = hover["contents"]["value"].as_str().unwrap();
        assert!(hover_text.contains("完整限定名称"), "{hover_text}");
        assert!(hover_text.contains("可描述"), "{hover_text}");
        assert!(hover_text.contains("公开成员"), "{hover_text}");
        let rejected = semantic_response(
            "textDocument/rename",
            &main_uri,
            semantic_source,
            &request_for(&main_uri, "textDocument/rename", line, character, "新视图"),
        );
        assert!(rejected.is_null());

        let alias_character = last_position(semantic_source, "基础.视图", 0);
        let renamed = semantic_response(
            "textDocument/rename",
            &main_uri,
            semantic_source,
            &request_for(
                &main_uri,
                "textDocument/rename",
                alias_character.0,
                alias_character.1,
                "核心",
            ),
        );
        let edits = renamed["changes"][&main_uri].as_array().unwrap();
        assert_eq!(edits.len(), 3);
        assert!(edits.iter().all(|edit| edit["newText"] == "核心"));

        let reexport_source =
            "引「facade.yx」为 门面；\n定 值：门面.控件.按钮 为 门面.控件.按钮（）；\n";
        std::fs::write(&main_path, reexport_source).unwrap();
        let (line, character) = last_position(reexport_source, "门面.控件.按钮", 6);
        let reexport_definition = semantic_response(
            "textDocument/definition",
            &main_uri,
            reexport_source,
            &request_for(
                &main_uri,
                "textDocument/definition",
                line,
                character,
                "未用",
            ),
        );
        assert_eq!(
            reexport_definition["uri"],
            canonical_uri(root.join("controls.yx"))
        );
        let reexport_hover = semantic_response(
            "textDocument/hover",
            &main_uri,
            reexport_source,
            &request_for(&main_uri, "textDocument/hover", line, character, "未用"),
        );
        let reexport_hover_text = reexport_hover["contents"]["value"].as_str().unwrap();
        assert!(
            reexport_hover_text.contains("父类"),
            "{reexport_hover_text}"
        );
        assert!(
            reexport_hover_text.contains("base.yx.视图"),
            "{reexport_hover_text}"
        );

        let same_name_source = "引「a.yx」为 甲；引「b.yx」为 乙；\n定 左：甲.节点 为 甲.节点（）；\n定 右：乙.节点 为 乙.节点（）；\n";
        std::fs::write(&main_path, same_name_source).unwrap();
        for (path_text, target) in [("甲.节点", "a.yx"), ("乙.节点", "b.yx")] {
            let (line, character) = last_position(same_name_source, path_text, 2);
            let definition = semantic_response(
                "textDocument/definition",
                &main_uri,
                same_name_source,
                &request_for(
                    &main_uri,
                    "textDocument/definition",
                    line,
                    character,
                    "未用",
                ),
            );
            assert_eq!(definition["uri"], canonical_uri(root.join(target)));
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}
