//! Windows ACL planning and application helpers.
//!
//! Planning is pure data ([`build_plan`]) so it can be compared against the
//! policy without touching a single ACL; the launcher only executes the plan in
//! `windows.rs`.
//!
//! Semantics mirror the Linux planner:
//!
//! - `protected` always wins: a writable rule covered by a protected path is
//!   dropped from the allow list;
//! - writable roots that do not exist are reported in [`AclPlan::skipped`] (an
//!   ACL cannot be attached to a missing path);
//! - unlike Landlock, a protected path nested inside a writable root *is*
//!   enforceable, because a deny ACE can subtract a subtree.

use std::path::{Path, PathBuf};

use crate::policy::{PathRule, SandboxPolicy};

/// `FILE_GENERIC_READ` (specific rights only).
pub const FILE_GENERIC_READ: u32 = 0x0012_0089;
/// `FILE_GENERIC_WRITE` (specific rights only).
pub const FILE_GENERIC_WRITE: u32 = 0x0012_0116;
/// `FILE_GENERIC_EXECUTE` (specific rights only).
pub const FILE_GENERIC_EXECUTE: u32 = 0x0012_00A0;
/// `DELETE` on the object itself.
pub const DELETE: u32 = 0x0001_0000;
/// `FILE_DELETE_CHILD` on a directory: required to delete entries inside it.
pub const FILE_DELETE_CHILD: u32 = 0x0000_0040;

/// Access granted on a writable directory: read, write, execute, delete.
///
/// Written with *specific* access bits, never `GENERIC_*`: the object manager
/// rewrites generic bits into specific ones when the ACE is stored, which would
/// make the ACE impossible to find again for the idempotency check and for
/// revocation.
///
/// `WRITE_DAC` and `WRITE_OWNER` are deliberately absent: the sandboxed process
/// must not be able to rewrite the very ACL that confines it.
pub const WORKSPACE_ALLOW: u32 =
    FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE | FILE_DELETE_CHILD;

/// Access granted on a single writable file (`FILE_DELETE_CHILD` is meaningless
/// there and would be rejected by the ACL editor for some object types).
pub const FILE_ALLOW: u32 = FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE;

/// Read+execute grant for read roots (specific rights only).
pub const READ_EXEC_ALLOW: u32 = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;

/// Permission bits that are denied on a `protected` path.
///
/// Only the write-specific bits are denied: an ACE that also denied
/// `READ_CONTROL` would be surprising on a path the agent may still read.
/// `FILE_DELETE_CHILD` is included because deleting an entry only needs write
/// access on its parent directory.
pub fn deny_write_mask() -> u32 {
    FILE_WRITE_DATA
        | FILE_APPEND_DATA
        | FILE_WRITE_EA
        | FILE_WRITE_ATTRIBUTES
        | DELETE
        | FILE_DELETE_CHILD
}

/// `FILE_WRITE_DATA` / `FILE_ADD_FILE` on a directory.
pub const FILE_WRITE_DATA: u32 = 0x0000_0002;
/// `FILE_APPEND_DATA` / `FILE_ADD_SUBDIRECTORY` on a directory.
pub const FILE_APPEND_DATA: u32 = 0x0000_0004;
/// `FILE_WRITE_EA`.
pub const FILE_WRITE_EA: u32 = 0x0000_0010;
/// `FILE_WRITE_ATTRIBUTES`.
pub const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;

/// One planned ACE.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AclEntry {
    /// Path the ACE is attached to.
    pub path: PathBuf,
    /// Access mask (without inheritance bits).
    pub mask: u32,
}

/// A plan the launcher executes against the real filesystem.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AclPlan {
    /// Allow ACEs for writable roots.
    pub allow: Vec<AclEntry>,
    /// Deny ACEs for protected paths.
    pub deny: Vec<AclEntry>,
    /// Writable rules that were dropped because the path does not exist.
    pub skipped: Vec<PathBuf>,
}

impl AclPlan {
    /// Whether the plan grants anything at all.
    pub fn is_empty(&self) -> bool {
        self.allow.is_empty() && self.deny.is_empty()
    }

    /// Every path the plan touches.
    pub fn paths(&self) -> Vec<PathBuf> {
        let mut paths: Vec<PathBuf> = self.allow.iter().map(|entry| entry.path.clone()).collect();
        for entry in &self.deny {
            if !paths.contains(&entry.path) {
                paths.push(entry.path.clone());
            }
        }
        paths
    }
}

/// Build the ACL plan for `policy`.
///
/// Duplicate paths are merged into a single entry with the union of their
/// masks, so repeated `--write` flags never stack ACEs.
pub fn build_plan(policy: &SandboxPolicy) -> AclPlan {
    let mut allow: Vec<AclEntry> = Vec::new();
    let mut deny: Vec<AclEntry> = Vec::new();
    let mut skipped: Vec<PathBuf> = Vec::new();

    for rule in policy
        .writable
        .iter()
        .chain(policy.allow_file_writes.iter())
    {
        if policy
            .protected
            .iter()
            .any(|protected| protected.matches(rule.path()))
        {
            // `protected` wins; dropping the rule is exact enforcement on
            // Windows because the deny ACE below covers the subtree.
            continue;
        }
        let mask = match rule {
            PathRule::Dir(_) => WORKSPACE_ALLOW,
            PathRule::File(_) => FILE_ALLOW,
        };
        let path = rule.path();
        if !path.exists() {
            if !skipped.contains(&path.to_path_buf()) {
                skipped.push(path.to_path_buf());
            }
            continue;
        }
        merge(&mut allow, path, mask);
    }

    for rule in &policy.protected {
        let path = rule.path();
        // A missing protected path is reported by `protection_gaps`; there is
        // nothing to attach a deny ACE to until it exists.
        if !path.exists() {
            continue;
        }
        merge(&mut deny, path, deny_write_mask());
    }

    AclPlan {
        allow,
        deny,
        skipped,
    }
}

fn merge(entries: &mut Vec<AclEntry>, path: &Path, mask: u32) {
    if let Some(existing) = entries.iter_mut().find(|entry| entry.path == path) {
        existing.mask |= mask;
    } else {
        entries.push(AclEntry {
            path: path.to_path_buf(),
            mask,
        });
    }
}

/// Whether the volume hosting `path` persists ACLs.
///
/// exFAT, FAT32, and many network shares silently ignore DACLs; granting a
/// capability SID there would produce no enforcement at all.
#[cfg(windows)]
pub fn volume_supports_acls(path: &Path) -> Result<bool, String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{GetVolumeInformationW, GetVolumePathNameW};

    /// `FILE_PERSISTENT_ACLS` from the `GetVolumeInformationW` flags.
    const FILE_PERSISTENT_ACLS: u32 = 0x0000_0008;

    fn wide(text: &std::ffi::OsStr) -> Vec<u16> {
        text.encode_wide().chain(std::iter::once(0)).collect()
    }

    let wide_path = wide(path.as_os_str());
    let mut volume = vec![0u16; 261];
    // SAFETY: `wide_path` is NUL-terminated and `volume` is a writable buffer
    // whose length is passed in characters.
    let ok =
        unsafe { GetVolumePathNameW(wide_path.as_ptr(), volume.as_mut_ptr(), volume.len() as u32) };
    if ok == 0 {
        return Err(format!(
            "cannot resolve the volume of {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    let mut flags: u32 = 0;
    // SAFETY: `volume` is the NUL-terminated volume root from the call above;
    // every optional output is NULL.
    let ok = unsafe {
        GetVolumeInformationW(
            volume.as_ptr(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut flags,
            std::ptr::null_mut(),
            0,
        )
    };
    if ok == 0 {
        return Err(format!(
            "cannot query the volume of {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(flags & FILE_PERSISTENT_ACLS != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::SandboxMode;

    fn policy(writable: Vec<PathRule>, protected: Vec<PathRule>) -> SandboxPolicy {
        SandboxPolicy {
            enabled: true,
            mode: SandboxMode::Auto,
            writable,
            protected,
            allow_file_writes: Vec::new(),
            approval: Default::default(),
            audit_log: None,
        }
    }

    #[test]
    fn writable_directories_get_the_full_workspace_mask() {
        let dir = tempfile::tempdir().unwrap();
        let plan = build_plan(&policy(
            vec![PathRule::Dir(dir.path().to_path_buf())],
            Vec::new(),
        ));
        assert_eq!(plan.allow.len(), 1);
        assert_eq!(plan.allow[0].mask, WORKSPACE_ALLOW);
        assert!(plan.skipped.is_empty());
        assert!(plan.deny.is_empty());
    }

    #[test]
    fn protected_paths_become_deny_entries_even_inside_writable_roots() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("secrets");
        std::fs::create_dir(&secret).unwrap();
        let plan = build_plan(&policy(
            vec![PathRule::Dir(dir.path().to_path_buf())],
            vec![PathRule::Dir(secret.clone())],
        ));
        assert_eq!(plan.allow.len(), 1, "the writable root stays granted");
        assert_eq!(plan.deny.len(), 1, "the nested secret is subtracted");
        assert_eq!(plan.deny[0].path, secret);
        assert_eq!(plan.deny[0].mask, deny_write_mask());
    }

    #[test]
    fn writable_rule_under_a_protected_path_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("secrets");
        let inner = secret.join("logs");
        std::fs::create_dir_all(&inner).unwrap();
        let plan = build_plan(&policy(
            vec![PathRule::Dir(inner.clone())],
            vec![PathRule::Dir(secret.clone())],
        ));
        assert!(plan.allow.is_empty(), "protected wins over a nested rule");
        assert_eq!(plan.deny.len(), 1);
    }

    #[test]
    fn missing_writable_roots_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("not-there");
        let plan = build_plan(&policy(vec![PathRule::Dir(missing.clone())], Vec::new()));
        assert!(plan.allow.is_empty());
        assert_eq!(plan.skipped, vec![missing]);
    }

    #[test]
    fn duplicate_roots_are_merged_not_stacked() {
        let dir = tempfile::tempdir().unwrap();
        let plan = build_plan(&policy(
            vec![
                PathRule::Dir(dir.path().to_path_buf()),
                PathRule::Dir(dir.path().to_path_buf()),
            ],
            Vec::new(),
        ));
        assert_eq!(plan.allow.len(), 1, "no duplicate ACEs");
        assert_eq!(plan.allow[0].mask, WORKSPACE_ALLOW);
    }

    #[test]
    fn deny_mask_covers_every_write_path() {
        let mask = deny_write_mask();
        for (name, bit) in [
            ("FILE_GENERIC_WRITE", FILE_GENERIC_WRITE),
            ("FILE_GENERIC_WRITE", FILE_GENERIC_WRITE),
            ("DELETE", DELETE),
            ("FILE_DELETE_CHILD", FILE_DELETE_CHILD),
        ] {
            assert_ne!(mask & bit, 0, "deny mask missing {name}");
        }
    }
}
