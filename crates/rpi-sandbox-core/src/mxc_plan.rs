//! Windows MXC plan.
//!
//! Microsoft Execution Containers take a filesystem policy instead of ACLs:
//! `readwrite_paths` and `readonly_paths`. Building that plan is pure path
//! arithmetic, so it is unit-tested on every host.
//!
//! Policy `readonly` is mapped to `readonly_paths`: MXC ranks a more specific
//! path above its parent, so a read-only subdirectory subtracts writes from a
//! writable root while staying readable.

use std::path::{Path, PathBuf};

use crate::policy::SandboxPolicy;

/// Filesystem sections of one MXC container request.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MxcPlan {
    /// Roots the workload may modify.
    pub readwrite: Vec<PathBuf>,
    /// Roots the workload may read.
    pub readonly: Vec<PathBuf>,
}

impl MxcPlan {
    /// Compile a policy plus the launcher's read roots into an MXC plan.
    ///
    /// MXC only exposes the directories listed here (plus its own system
    /// defaults), so the volume root of every writable/read root is added to
    /// `readonly`: rpi probes `\\?\C:\` while resolving resources and refuses
    /// to start without it.
    pub fn build(policy: &SandboxPolicy, read_roots: &[PathBuf]) -> Self {
        let mut readwrite: Vec<PathBuf> = policy
            .writable
            .iter()
            .map(|rule| rule.path().to_path_buf())
            .collect();
        dedupe(&mut readwrite);

        let mut readonly: Vec<PathBuf> = Vec::new();
        for root in &readwrite {
            push_volume_root(&mut readonly, root);
        }
        for root in read_roots {
            if root.as_os_str().is_empty() || !root.is_absolute() {
                continue;
            }
            // Read roots only grant read access. A writable root already
            // grants read, and putting the same path in both lists makes MXC
            // rank an exact duplicate ambiguously; skip it. The launcher's
            // directory is often the cwd, so this avoids turning cwd
            // read-only when `rpis` runs from the extracted archive.
            if readwrite
                .iter()
                .any(|writable| root == writable || root.starts_with(writable))
            {
                continue;
            }
            push_volume_root(&mut readonly, root);
            push_unique(&mut readonly, root.clone());
        }
        for rule in &policy.readonly {
            let path = rule.path().to_path_buf();
            if path.exists() {
                push_unique(&mut readonly, path);
            }
        }
        dedupe(&mut readonly);

        Self {
            readwrite,
            readonly,
        }
    }

    /// Human-readable lines for `rpis --print-plan`.
    pub fn describe(&self) -> Vec<String> {
        let mut lines = vec!["backend: windows-mxc".to_string()];
        for path in &self.readwrite {
            lines.push(format!("  write {}", path.display()));
        }
        for path in &self.readonly {
            lines.push(format!("  read  {}", path.display()));
        }
        lines
    }
}

/// Add the volume root (`C:\`) that contains `path`.
fn push_volume_root(roots: &mut Vec<PathBuf>, path: &Path) {
    if let Some(root) = path.ancestors().last() {
        push_unique(roots, root.to_path_buf());
    }
}

fn push_unique(paths: &mut Vec<PathBuf>, path: PathBuf) {
    if !paths.contains(&path) {
        paths.push(path);
    }
}

fn dedupe(paths: &mut Vec<PathBuf>) {
    let mut unique: Vec<PathBuf> = Vec::with_capacity(paths.len());
    for path in paths.drain(..) {
        if !unique.contains(&path) {
            unique.push(path);
        }
    }
    *paths = unique;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{PathRule, SandboxPolicy};

    fn policy(writable: &[&str], readonly: &[&str]) -> SandboxPolicy {
        SandboxPolicy {
            enabled: true,
            writable: writable
                .iter()
                .map(|path| PathRule::Dir(PathBuf::from(path)))
                .collect(),
            readonly: readonly
                .iter()
                .map(|path| PathRule::Dir(PathBuf::from(path)))
                .collect(),
            ..SandboxPolicy::default()
        }
    }

    #[test]
    fn writable_roots_become_readwrite_and_their_volume_root_is_readable() {
        let plan = MxcPlan::build(&policy(&[r"C:\work"], &[]), &[]);
        assert_eq!(plan.readwrite, vec![PathBuf::from(r"C:\work")]);
        assert_eq!(plan.readonly, vec![PathBuf::from(r"C:\")]);
    }

    #[test]
    fn read_roots_covered_by_writable_are_skipped() {
        let plan = MxcPlan::build(
            &policy(&[r"C:\work"], &[]),
            &[
                PathBuf::from(r"C:\work\agent"),
                PathBuf::from(r"C:\work"),
                PathBuf::from(r"C:\agent"),
            ],
        );
        let mut got = plan.readonly.clone();
        got.sort();
        let mut want = vec![PathBuf::from(r"C:\"), PathBuf::from(r"C:\agent")];
        want.sort();
        assert_eq!(got, want);
    }

    #[test]
    fn readonly_subdir_is_added_to_the_read_set() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("secret");
        std::fs::create_dir(&secret).unwrap();
        let plan = MxcPlan::build(
            &SandboxPolicy {
                enabled: true,
                writable: vec![PathRule::Dir(dir.path().to_path_buf())],
                readonly: vec![PathRule::Dir(secret.clone())],
                ..SandboxPolicy::default()
            },
            &[],
        );
        assert!(plan.readwrite.contains(&dir.path().to_path_buf()));
        assert!(plan.readonly.contains(&secret));
    }

    #[test]
    fn missing_readonly_paths_are_skipped() {
        let plan = MxcPlan::build(&policy(&[r"C:\work"], &[r"C:\does-not-exist"]), &[]);
        assert!(!plan.readonly.contains(&PathBuf::from(r"C:\does-not-exist")));
    }

    #[test]
    fn the_plan_describes_every_section() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("secret");
        std::fs::create_dir(&secret).unwrap();
        let plan = MxcPlan::build(
            &SandboxPolicy {
                enabled: true,
                writable: vec![PathRule::Dir(dir.path().to_path_buf())],
                readonly: vec![PathRule::Dir(secret)],
                ..SandboxPolicy::default()
            },
            &[],
        );
        let text = plan.describe().join("\n");
        assert!(text.contains("windows-mxc"));
        assert!(text.contains("write "));
        assert!(text.contains("read "));
    }
}
