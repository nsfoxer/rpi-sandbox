//! Windows MXC plan.
//!
//! Microsoft Execution Containers take a filesystem policy instead of ACLs:
//! `readwrite_paths`, `readonly_paths`, and `denied_paths`. Building that plan
//! is pure path arithmetic, so it is unit-tested on every host.

use std::path::{Path, PathBuf};

use crate::policy::SandboxPolicy;

/// Filesystem sections of one MXC container request.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MxcPlan {
    /// Roots the workload may modify.
    pub readwrite: Vec<PathBuf>,
    /// Roots the workload may read.
    pub readonly: Vec<PathBuf>,
    /// Subpaths that stay inaccessible even inside a readable root.
    pub denied: Vec<PathBuf>,
}

impl MxcPlan {
    /// Compile a policy plus the launcher's read roots into an MXC plan.
    ///
    /// MXC only exposes the directories listed here (plus its own system
    /// defaults), so the volume root of every writable/read root is added to
    /// `readonly`: rpi probes `\\?\C:\` while resolving resources and refuses
    /// to start without it. `denied` keeps `protected` subtractive.
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
            push_volume_root(&mut readonly, root);
            push_unique(&mut readonly, root.clone());
        }
        dedupe(&mut readonly);

        let mut denied: Vec<PathBuf> = policy
            .protected
            .iter()
            .map(|rule| rule.path().to_path_buf())
            .filter(|path| path.exists())
            .collect();
        dedupe(&mut denied);

        Self {
            readwrite,
            readonly,
            denied,
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
        for path in &self.denied {
            lines.push(format!("  deny  {}", path.display()));
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

    fn policy(writable: &[&str], protected: &[&str]) -> SandboxPolicy {
        SandboxPolicy {
            enabled: true,
            writable: writable
                .iter()
                .map(|path| PathRule::Dir(PathBuf::from(path)))
                .collect(),
            protected: protected
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
        assert!(plan.denied.is_empty());
    }

    #[test]
    fn read_roots_are_added_once() {
        let plan = MxcPlan::build(
            &policy(&[r"C:\work"], &[]),
            &[PathBuf::from(r"C:\work\agent"), PathBuf::from(r"C:\work")],
        );
        let mut got = plan.readonly.clone();
        got.sort();
        let mut want = vec![
            PathBuf::from(r"C:\"),
            PathBuf::from(r"C:\work"),
            PathBuf::from(r"C:\work\agent"),
        ];
        want.sort();
        assert_eq!(got, want);
    }

    #[test]
    fn missing_protected_paths_are_skipped() {
        let plan = MxcPlan::build(&policy(&[r"C:\work"], &[r"C:\does-not-exist"]), &[]);
        assert!(plan.denied.is_empty());
    }

    #[test]
    fn the_plan_describes_every_section() {
        let plan = MxcPlan::build(&policy(&[r"C:\work"], &[]), &[PathBuf::from(r"C:\agent")]);
        let text = plan.describe().join("\n");
        assert!(text.contains("windows-mxc"));
        assert!(text.contains("write C:\\work"));
        assert!(text.contains("read  C:\\agent"));
    }
}
