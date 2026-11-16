//! Cross-run bookkeeping locations.
//!
//! Everything the sandbox must remember between runs (the policy snapshot the
//! extension reads, the Windows ACL journal, the launcher lock) lives under one
//! directory so cleanup and diagnostics have a single place to look.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// Root of the sandbox state directory.
///
/// Resolution order:
/// 1. `RPI_SANDBOX_STATE_DIR` (tests, packaging);
/// 2. `RPI_CODING_AGENT_DIR/sandbox`;
/// 3. `~/.rpi/agent/sandbox` (`HOME` or `USERPROFILE`);
/// 4. `<temp>/rpi-sandbox`.
pub fn state_dir() -> PathBuf {
    if let Some(dir) = non_empty_var("RPI_SANDBOX_STATE_DIR") {
        return PathBuf::from(dir);
    }
    if let Some(dir) = non_empty_var("RPI_CODING_AGENT_DIR") {
        return PathBuf::from(dir).join("sandbox");
    }
    if let Some(home) = non_empty_var("HOME").or_else(|| non_empty_var("USERPROFILE")) {
        return PathBuf::from(home).join(".rpi/agent/sandbox");
    }
    std::env::temp_dir().join("rpi-sandbox")
}

/// Directory holding Windows ACL journals.
pub fn acl_journal_dir() -> PathBuf {
    state_dir().join("acl")
}

/// Path of the policy snapshot for one launcher run.
pub fn policy_snapshot_path(nonce: u128) -> PathBuf {
    state_dir().join(format!("policy-{}-{nonce:x}.json", std::process::id()))
}

/// A fresh enough nonce for file names.
pub fn nonce() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0)
}

/// Create the state directory tree if needed.
pub fn ensure_state_dir() -> std::io::Result<PathBuf> {
    let dir = state_dir();
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Delete policy snapshots older than `max_age`.
///
/// The launcher writes one snapshot per run and the Unix launcher cannot delete
/// it after `exec`, so stale files are collected at the next startup. Snapshots
/// are only read once, when the extension loads, so deleting an old one is
/// harmless even if its rpi process is still running.
pub fn sweep_policy_snapshots(max_age: std::time::Duration) -> usize {
    let dir = state_dir();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !name.starts_with("policy-") || !name.ends_with(".json") {
            continue;
        }
        let stale = entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .ok()
            .and_then(|modified| modified.elapsed().ok())
            .map(|age| age > max_age)
            .unwrap_or(false);
        if stale && std::fs::remove_file(&path).is_ok() {
            removed += 1;
        }
    }
    removed
}

fn non_empty_var(name: &str) -> Option<std::ffi::OsString> {
    std::env::var_os(name).filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_dir_is_absolute_and_named() {
        let dir = state_dir();
        assert!(dir.is_absolute(), "{}", dir.display());
        assert!(dir.to_string_lossy().contains("sandbox") || dir.ends_with("rpi-sandbox"));
    }

    #[test]
    fn snapshot_names_are_unique_per_process_and_nonce() {
        let first = policy_snapshot_path(1);
        let second = policy_snapshot_path(2);
        assert_ne!(first, second);
        assert_eq!(
            first.parent().unwrap(),
            second.parent().unwrap(),
            "snapshots live in one directory"
        );
    }
}
