//! Path normalization and resolution helpers shared by policy and broker.
//!
//! Write targets usually do not exist yet, so they cannot always be
//! canonicalized directly. [`normalize_and_resolve`] resolves the deepest
//! existing ancestor (which follows symlinked roots such as `/home` ->
//! `/var/home` on Fedora) and appends the missing components verbatim. Rules and
//! runtime lookups therefore agree on the same absolute path.

use std::path::{Component, Path, PathBuf};

/// Canonicalize when possible, otherwise normalize lexically.
///
/// The target may not exist yet (a write target, a captured session directory).
/// Resolving the deepest existing ancestor is what enforcement compares
/// against, because symlinked roots must be resolved before matching rules.
pub fn normalize_and_resolve(path: &Path) -> PathBuf {
    let normalized = lexical_normalize(path);
    if !normalized.is_absolute() {
        return normalized;
    }
    if let Ok(resolved) = std::fs::canonicalize(&normalized) {
        return resolved;
    }
    let mut suffix: Vec<std::ffi::OsString> = Vec::new();
    let mut current = normalized.as_path();
    while let Some(parent) = current.parent() {
        if let Some(name) = current.file_name() {
            suffix.push(name.to_os_string());
        }
        if let Ok(base) = std::fs::canonicalize(parent) {
            let mut out = base;
            for component in suffix.iter().rev() {
                out.push(component);
            }
            return lexical_normalize(&out);
        }
        current = parent;
    }
    normalized
}

/// Remove `.` and `..` components without touching the filesystem.
pub fn lexical_normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => out.push(prefix.as_os_str()),
            Component::RootDir => out.push(Component::RootDir.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(part) => out.push(part),
        }
    }
    out
}

/// Validate that `path` is absolute and does not climb above the filesystem
/// root through `..` components.
///
/// Returns the lexically normalized path. Relative paths and escaping paths
/// return `None`; callers map that to the protocol's `invalid_path` code.
pub fn absolute_lexical(path: &Path) -> Option<PathBuf> {
    if !path.is_absolute() || has_nul(path) {
        return None;
    }
    let mut out = PathBuf::new();
    let mut depth = 0_usize;
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => out.push(prefix.as_os_str()),
            Component::RootDir => {
                out.push(Component::RootDir.as_os_str());
                depth = 0;
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if depth == 0 {
                    return None;
                }
                out.pop();
                depth -= 1;
            }
            Component::Normal(part) => {
                out.push(part);
                depth += 1;
            }
        }
    }
    Some(out)
}

/// Whether the path contains a NUL byte (invalid in a real filesystem path).
pub fn has_nul(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        path.as_os_str().as_bytes().contains(&0)
    }
    #[cfg(not(unix))]
    {
        path.to_string_lossy().contains('\0')
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lexical_normalization_removes_dots() {
        assert_eq!(
            lexical_normalize(Path::new("/a/./b/../c")),
            PathBuf::from("/a/c")
        );
    }

    #[test]
    fn absolute_paths_must_not_escape_the_root() {
        assert_eq!(
            absolute_lexical(Path::new("/a/../b")),
            Some(PathBuf::from("/b"))
        );
        assert_eq!(absolute_lexical(Path::new("/../b")), None);
        assert_eq!(absolute_lexical(Path::new("relative")), None);
    }

    #[cfg(unix)]
    #[test]
    fn deepest_existing_ancestor_resolves_symlinks() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        let link = dir.path().join("link");
        std::fs::create_dir(&real).unwrap();
        symlink(&real, &link).unwrap();

        let resolved = normalize_and_resolve(&link.join("missing.txt"));
        assert_eq!(resolved, real.join("missing.txt"));
    }

    #[test]
    fn relative_paths_stay_lexical() {
        assert_eq!(
            normalize_and_resolve(Path::new("a/../b")),
            PathBuf::from("b")
        );
    }
}
