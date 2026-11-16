//! Append-only audit log shared by the broker, the launcher, and (through the
//! broker) the extension.
//!
//! One JSON object per line; failures never abort the operation that produced
//! them, they only print a warning.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// One audit record.
#[derive(Clone, Copy, Debug)]
pub struct AuditEvent<'a> {
    /// Operation name (`write`, `acl_apply`, `journal_replay`, ...).
    pub op: &'a str,
    /// Primary path, or `-`.
    pub path: &'a str,
    /// Whether the operation succeeded.
    pub ok: bool,
    /// Failure detail.
    pub error: Option<&'a str>,
    /// Approval scope, when the record comes from the broker.
    pub scope: Option<&'a str>,
}

/// Append-only JSON Lines log.
#[derive(Debug, Default)]
pub struct AuditLog {
    file: Option<File>,
}

impl AuditLog {
    /// Open `path` for appending. `None` disables logging.
    pub fn open(path: Option<&Path>) -> Self {
        let Some(path) = path else {
            return Self::default();
        };
        if let Some(parent) = path.parent() {
            if let Err(error) = std::fs::create_dir_all(parent) {
                eprintln!(
                    "warning: sandbox audit directory {} is unavailable: {error}",
                    parent.display()
                );
            }
        }
        match OpenOptions::new().create(true).append(true).open(path) {
            Ok(file) => Self { file: Some(file) },
            Err(error) => {
                eprintln!(
                    "warning: sandbox audit log {} is unavailable: {error}",
                    path.display()
                );
                Self::default()
            }
        }
    }

    /// Whether a log file is open.
    pub fn is_enabled(&self) -> bool {
        self.file.is_some()
    }

    /// Append one record. Write failures are reported once per call and never
    /// propagate.
    pub fn record(&mut self, event: AuditEvent<'_>) {
        let Some(file) = self.file.as_mut() else {
            return;
        };
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        let entry = serde_json::json!({
            "time": seconds,
            "op": event.op,
            "path": event.path,
            "ok": event.ok,
            "error": event.error,
            "scope": event.scope,
        });
        if let Err(failure) = writeln!(file, "{entry}").and_then(|()| file.flush()) {
            eprintln!("warning: sandbox audit write failed: {failure}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_are_json_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut log = AuditLog::open(Some(&path));
        assert!(log.is_enabled());
        log.record(AuditEvent {
            op: "acl_apply",
            path: r"C:\work",
            ok: true,
            error: None,
            scope: None,
        });
        log.record(AuditEvent {
            op: "write",
            path: r"C:\work\a.txt",
            ok: false,
            error: Some("denied"),
            scope: Some("session"),
        });
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["op"], "acl_apply");
        assert_eq!(first["ok"], true);
        let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(second["scope"], "session");
    }

    #[test]
    fn no_path_means_no_file() {
        let mut log = AuditLog::open(None);
        assert!(!log.is_enabled());
        log.record(AuditEvent {
            op: "write",
            path: "-",
            ok: true,
            error: None,
            scope: None,
        });
    }
}
