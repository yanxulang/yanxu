//! Shared canonical identities for modules and object declarations.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "namespace", rename_all = "snake_case")]
pub enum ModuleId {
    Standard { name: String },
    Package { package: String, module: String },
    Archive { module: String },
    File { canonical_path: String },
    Memory { name: String },
}

impl ModuleId {
    pub fn standard(name: impl Into<String>) -> Self {
        Self::Standard { name: name.into() }
    }

    pub fn archive(module: impl Into<String>) -> Self {
        Self::Archive {
            module: module.into(),
        }
    }

    pub fn for_source(name: &str) -> Self {
        if name.starts_with("app:") || name.starts_with("pkg:") {
            return Self::archive(name);
        }
        let path = Path::new(name);
        if path.is_absolute() || path.exists() {
            return Self::for_path(path);
        }
        Self::Memory { name: name.into() }
    }

    pub fn for_path(path: &Path) -> Self {
        let canonical = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        if let Some(base) = canonical.parent()
            && let Ok(Some(manifest)) = crate::package::discover(base)
        {
            let root = fs::canonicalize(&manifest.root).unwrap_or(manifest.root);
            if let Ok(relative) = canonical.strip_prefix(&root) {
                return Self::Package {
                    package: format!("{}@{}", manifest.name, manifest.version),
                    module: portable_path(relative),
                };
            }
        }
        Self::File {
            canonical_path: portable_path(&canonical),
        }
    }

    pub fn is_valid(&self) -> bool {
        match self {
            Self::Standard { name } | Self::Memory { name } => valid_component(name),
            Self::Package { package, module } => {
                valid_component(package) && valid_module_path(module)
            }
            Self::Archive { module } => valid_module_path(module),
            Self::File { canonical_path } => {
                !canonical_path.is_empty() && !canonical_path.chars().any(char::is_control)
            }
        }
    }
}

impl fmt::Display for ModuleId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Standard { name } => write!(formatter, "标准:{name}"),
            Self::Package { package, module } => write!(formatter, "包:{package}/{module}"),
            Self::Archive { module } => write!(formatter, "归档:{module}"),
            Self::File { canonical_path } => write!(formatter, "文件:{canonical_path}"),
            Self::Memory { name } => write!(formatter, "内存:{name}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypeDeclarationKind {
    Class,
    Protocol,
}

impl fmt::Display for TypeDeclarationKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Class => "类",
            Self::Protocol => "协",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TypeId {
    pub module: ModuleId,
    pub name: String,
    pub kind: TypeDeclarationKind,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RuntimeTypePath {
    pub segments: Vec<String>,
}

impl RuntimeTypePath {
    pub fn new(segments: Vec<String>) -> Self {
        Self { segments }
    }

    pub fn single(name: impl Into<String>) -> Self {
        Self {
            segments: vec![name.into()],
        }
    }

    pub fn single_name(&self) -> Option<&str> {
        match self.segments.as_slice() {
            [name] => Some(name),
            _ => None,
        }
    }

    pub fn is_valid(&self) -> bool {
        !self.segments.is_empty()
            && self
                .segments
                .iter()
                .all(|segment| valid_type_component(segment))
    }
}

impl fmt::Display for RuntimeTypePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.segments.join("."))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TypeLink {
    pub source: RuntimeTypePath,
    pub target: Option<TypeId>,
}

impl TypeLink {
    pub fn unresolved(source: RuntimeTypePath) -> Self {
        Self {
            source,
            target: None,
        }
    }

    pub fn resolved(source: RuntimeTypePath, target: TypeId) -> Self {
        Self {
            source,
            target: Some(target),
        }
    }

    pub fn is_valid(&self) -> bool {
        self.source.is_valid()
            && self.target.as_ref().is_none_or(|target| {
                target.is_valid()
                    && self
                        .source
                        .segments
                        .last()
                        .is_some_and(|name| name == &target.name)
            })
    }
}

impl fmt::Display for TypeLink {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.source)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RuntimeType {
    Named {
        link: TypeLink,
    },
    Union {
        variants: Vec<RuntimeType>,
    },
    Nullable {
        inner: Box<RuntimeType>,
    },
    Generic {
        base: TypeLink,
        arguments: Vec<RuntimeType>,
    },
    Function {
        parameters: Vec<RuntimeType>,
        result: Box<RuntimeType>,
    },
}

impl RuntimeType {
    pub fn named(name: impl Into<String>) -> Self {
        Self::Named {
            link: TypeLink::unresolved(RuntimeTypePath::single(name)),
        }
    }

    pub fn is_valid(&self) -> bool {
        match self {
            Self::Named { link } => link.is_valid(),
            Self::Union { variants } => {
                variants.len() >= 2 && variants.iter().all(RuntimeType::is_valid)
            }
            Self::Nullable { inner } => inner.is_valid(),
            Self::Generic { base, arguments } => {
                base.is_valid()
                    && !arguments.is_empty()
                    && arguments.iter().all(RuntimeType::is_valid)
            }
            Self::Function { parameters, result } => {
                parameters.iter().all(RuntimeType::is_valid) && result.is_valid()
            }
        }
    }
}

impl fmt::Display for RuntimeType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Named { link } => write!(formatter, "{link}"),
            Self::Union { variants } => {
                for (index, variant) in variants.iter().enumerate() {
                    if index > 0 {
                        formatter.write_str("|")?;
                    }
                    write!(formatter, "{variant}")?;
                }
                Ok(())
            }
            Self::Nullable { inner } => write!(formatter, "{inner}?"),
            Self::Generic { base, arguments } => {
                write!(formatter, "{base}<")?;
                for (index, argument) in arguments.iter().enumerate() {
                    if index > 0 {
                        formatter.write_str("，")?;
                    }
                    write!(formatter, "{argument}")?;
                }
                formatter.write_str(">")
            }
            Self::Function { parameters, result } => {
                formatter.write_str("法（")?;
                for (index, parameter) in parameters.iter().enumerate() {
                    if index > 0 {
                        formatter.write_str("，")?;
                    }
                    write!(formatter, "{parameter}")?;
                }
                write!(formatter, "）：{result}")
            }
        }
    }
}

impl TypeId {
    pub fn new(module: ModuleId, name: impl Into<String>, kind: TypeDeclarationKind) -> Self {
        Self {
            module,
            name: name.into(),
            kind,
        }
    }

    pub fn qualified_name(&self) -> String {
        format!("{}.{}", self.module, self.name)
    }

    pub fn is_valid(&self) -> bool {
        self.module.is_valid() && valid_type_component(&self.name)
    }
}

impl fmt::Display for TypeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{name}", self.module, name = self.name)
    }
}

fn valid_component(value: &str) -> bool {
    !value.is_empty() && !value.chars().any(char::is_control) && !value.contains(['/', '\\'])
}

fn valid_type_component(value: &str) -> bool {
    valid_component(value) && !value.contains('.')
}

fn valid_module_path(value: &str) -> bool {
    let logical_path = value.rsplit_once(':').map_or(value, |(_, path)| path);
    !value.is_empty()
        && !logical_path.is_empty()
        && !value.chars().any(char::is_control)
        && !value.contains('\\')
        && !Path::new(value).is_absolute()
        && !Path::new(logical_path).is_absolute()
        && logical_path
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

fn portable_path(path: &Path) -> String {
    let mut output = PathBuf::new();
    for component in path.components() {
        output.push(component.as_os_str());
    }
    output
        .to_string_lossy()
        .replace(std::path::MAIN_SEPARATOR, "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aliases_do_not_participate_in_type_identity() {
        let module = ModuleId::archive("app:base.yx");
        let through_first_alias = TypeId::new(module.clone(), "视图", TypeDeclarationKind::Class);
        let through_second_alias = TypeId::new(module, "视图", TypeDeclarationKind::Class);
        assert_eq!(through_first_alias, through_second_alias);
        assert!(through_first_alias.is_valid());
        assert_eq!(
            serde_json::from_str::<TypeId>(&serde_json::to_string(&through_first_alias).unwrap())
                .unwrap(),
            through_first_alias
        );
    }

    #[test]
    fn same_short_name_in_distinct_modules_has_distinct_identity() {
        let left = TypeId::new(
            ModuleId::archive("app:a.yx"),
            "节点",
            TypeDeclarationKind::Class,
        );
        let right = TypeId::new(
            ModuleId::archive("app:b.yx"),
            "节点",
            TypeDeclarationKind::Class,
        );
        assert_ne!(left, right);
    }

    #[test]
    fn portable_module_ids_reject_absolute_and_parent_paths() {
        assert!(!ModuleId::archive("/tmp/app:main.yx").is_valid());
        assert!(!ModuleId::archive("app:../main.yx").is_valid());
        assert!(!ModuleId::archive("app:lib//main.yx").is_valid());
        assert!(ModuleId::archive("app:lib/main.yx").is_valid());
        assert!(ModuleId::archive("pkg:工具@1.0.0/src/main.yx").is_valid());
    }
}
