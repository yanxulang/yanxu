use std::path::{Path, PathBuf};

pub fn cargo_target_dir(manifest_root: &Path) -> PathBuf {
    let configured = std::env::var_os("CARGO_TARGET_DIR")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    resolve_target_dir(manifest_root, configured)
}

fn resolve_target_dir(manifest_root: &Path, configured: Option<PathBuf>) -> PathBuf {
    match configured {
        Some(configured) if configured.is_absolute() => configured,
        Some(configured) => manifest_root.join(configured),
        None => manifest_root.join("target"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_relative_and_absolute_target_directories() {
        let root = Path::new("/workspace/yanxu");
        assert_eq!(
            resolve_target_dir(root, Some(PathBuf::from("build/target"))),
            root.join("build/target")
        );
        assert_eq!(
            resolve_target_dir(root, Some(PathBuf::from("/tmp/yanxu-target"))),
            PathBuf::from("/tmp/yanxu-target")
        );
        assert_eq!(resolve_target_dir(root, None), root.join("target"));
    }
}
