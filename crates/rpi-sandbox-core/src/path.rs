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
        // Windows `canonicalize` returns extended-length paths (`\\?\C:\...`).
        // Normalizing strips that marker so policy rules, environment values,
        // and user-facing messages all use the same spelling.
        return lexical_normalize(&resolved);
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
///
/// On Windows this also strips the `\\?\` verbatim marker so paths returned by
/// `canonicalize` compare equal to paths built from configuration.
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
    #[cfg(windows)]
    {
        out = strip_verbatim(out);
    }
    out
}

/// Drop the `\\?\` / `\\?\UNC\` prefix from a normalized Windows path.
#[cfg(windows)]
fn strip_verbatim(path: PathBuf) -> PathBuf {
    use std::path::Prefix;

    let mut components = path.components();
    let Some(Component::Prefix(prefix)) = components.next() else {
        return path;
    };
    let mut out = match prefix.kind() {
        Prefix::VerbatimDisk(letter) => PathBuf::from(format!("{}:", letter as char)),
        Prefix::VerbatimUNC(server, share) => {
            let mut out = PathBuf::from(r"\\");
            out.push(server);
            out.push(share);
            out
        }
        _ => return path,
    };
    for component in components {
        match component {
            Component::RootDir => out.push(Component::RootDir.as_os_str()),
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Reject paths that cannot address a regular file or directory locally.
///
/// The broker is the one component that performs writes with an unconfined
/// token, so it must never accept a device namespace path such as
/// `\\.\PhysicalDrive0` or `\\?\GLOBALROOT\...`. Those are syntactically
/// absolute but do not resolve through the policy's notion of a filesystem.
pub fn validate_local_path(path: &Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        use std::path::Prefix;

        let mut components = path.components();
        let Some(Component::Prefix(prefix)) = components.next() else {
            return Err(format!("path must be fully qualified: {}", path.display()));
        };
        match prefix.kind() {
            Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => {
                if !matches!(components.next(), Some(Component::RootDir)) {
                    return Err(format!(
                        "drive-relative paths are not allowed: {} (use {}:\\...)",
                        path.display(),
                        letter as char
                    ));
                }
            }
            Prefix::UNC(..) | Prefix::VerbatimUNC(..) => {
                if !matches!(components.next(), Some(Component::RootDir)) {
                    return Err(format!("malformed UNC path: {}", path.display()));
                }
            }
            _ => {
                return Err(format!(
                    "device-namespace paths are not allowed: {}",
                    path.display()
                ))
            }
        }
    }
    #[cfg(not(windows))]
    {
        let _ = path;
    }
    Ok(())
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

    #[cfg(unix)]
    #[test]
    fn absolute_paths_must_not_escape_the_root() {
        assert_eq!(
            absolute_lexical(Path::new("/a/../b")),
            Some(PathBuf::from("/b"))
        );
        assert_eq!(absolute_lexical(Path::new("/../b")), None);
        assert_eq!(absolute_lexical(Path::new("relative")), None);
    }

    #[cfg(windows)]
    #[test]
    fn absolute_paths_must_not_escape_the_root() {
        assert_eq!(
            absolute_lexical(Path::new(r"C:\a\..\b")),
            Some(PathBuf::from(r"C:\b"))
        );
        assert_eq!(absolute_lexical(Path::new(r"C:\..\b")), None);
        assert_eq!(absolute_lexical(Path::new(r"relative\b")), None);
        assert_eq!(
            absolute_lexical(Path::new("relative")),
            None,
            "a bare file name is not absolute on Windows"
        );
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

    #[cfg(windows)]
    #[test]
    fn verbatim_prefixes_are_stripped() {
        assert_eq!(
            lexical_normalize(Path::new(r"\\?\C:\work\a.txt")),
            PathBuf::from(r"C:\work\a.txt")
        );
        assert_eq!(
            lexical_normalize(Path::new(r"\\?\UNC\server\share\a.txt")),
            PathBuf::from(r"\\server\share\a.txt")
        );
        // An existing directory returned by `canonicalize` must not expose the
        // verbatim marker either.
        let dir = tempfile::tempdir().unwrap();
        let resolved = normalize_and_resolve(dir.path());
        assert!(
            !resolved.to_string_lossy().starts_with(r"\\?\"),
            "canonicalize must not leak the verbatim marker: {}",
            resolved.display()
        );
    }

    #[cfg(windows)]
    #[test]
    fn device_namespace_paths_are_rejected() {
        assert!(validate_local_path(Path::new(r"\\.\PhysicalDrive0")).is_err());
        assert!(validate_local_path(Path::new(r"\\?\GLOBALROOT\Device\HarddiskVolume1")).is_err());
        assert!(
            validate_local_path(Path::new(r"C:relative")).is_err(),
            "drive-relative paths are ambiguous"
        );
        assert!(validate_local_path(Path::new(r"C:\work\a.txt")).is_ok());
        assert!(validate_local_path(Path::new(r"\\server\share\a.txt")).is_ok());
    }

    #[cfg(not(windows))]
    #[test]
    fn local_path_validation_is_a_no_op_off_windows() {
        assert!(validate_local_path(Path::new("/tmp/a")).is_ok());
    }
}
