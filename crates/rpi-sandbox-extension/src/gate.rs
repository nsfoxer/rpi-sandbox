//! Tool-call gating and out-of-policy write routing.
//!
//! In-policy writes are left to the built-in tool: the kernel domain already
//! permits them. Out-of-policy writes need an explicit user approval and are
//! performed by the unconfined broker, because the sandboxed process can never
//! write there itself.
//!
//! The logic is expressed against small traits so it can be tested without a
//! host process or a real dialog.

use std::path::Path;

use rpi_sandbox_core::{Access, ApprovalScope, SandboxPolicy, WriteOp};
use serde_json::Value;

use crate::config;
use crate::dialog::{self, Answer, DialogHost, PermissionRequest};

/// Broker operations the gate needs.
pub trait BrokerOps {
    /// Record an approval.
    fn approve(
        &self,
        path: &Path,
        operations: &[WriteOp],
        scope: ApprovalScope,
        recursive: bool,
    ) -> Result<(), String>;
    /// Whether an approval already covers the path (without consuming it).
    fn is_approved(&self, path: &Path, operation: WriteOp) -> bool;
    /// Perform the approved write.
    fn write(&self, path: &Path, data: &[u8]) -> Result<(), String>;
}

/// Frontend used to ask the user.
pub trait Approver {
    /// Show the permission prompt (or deny in headless runs).
    fn ask(&self, request: &PermissionRequest) -> Answer;
}

/// Production approver: `UiDialog` through the host runtime action.
pub struct UiApprover<'a> {
    /// Host dialog transport.
    pub host: &'a dyn DialogHost,
}

impl Approver for UiApprover<'_> {
    fn ask(&self, request: &PermissionRequest) -> Answer {
        dialog::ask(self.host, request)
    }
}

/// What the ToolCall handler should do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Let the built-in tool run; the kernel boundary permits the write.
    AllowTool,
    /// The broker performed the write; veto the built-in tool so it does not
    /// try (and fail) to write a protected path.
    HandledThroughBroker,
}

/// Gate one write/edit tool call.
///
/// `Err` carries the actionable reason shown in logs; the ToolCall handler
/// turns it into a veto.
pub fn handle_write(
    policy: &SandboxPolicy,
    isolated: bool,
    cwd: &Path,
    approver: &dyn Approver,
    broker: Option<&dyn BrokerOps>,
    tool_call_id: &str,
    verb: &str,
    raw_path: &str,
    data: &[u8],
) -> Result<Outcome, String> {
    let resolved = config::resolve_tool_path(cwd, raw_path);
    match policy.classify(&resolved) {
        Access::Writable => return Ok(Outcome::AllowTool),
        Access::Protected => {
            return Err(format!(
                "{} is protected by sandbox policy and cannot be written",
                resolved.display()
            ))
        }
        Access::ReadOnly => {}
    }

    if !isolated {
        return Err(format!(
            "{} is outside sandbox.writable; this process is NOT isolated, so out-of-policy \
             writes are advisory-only. Start rpi through rpi-sandbox or add the path to \
             sandbox.writable.",
            resolved.display()
        ));
    }
    if !policy.approval.is_enabled() {
        return Err(format!(
            "{} is outside sandbox.writable and approvals are disabled",
            resolved.display()
        ));
    }
    let Some(broker) = broker else {
        return Err(format!(
            "{} is outside sandbox.writable and the approval broker is unavailable",
            resolved.display()
        ));
    };

    // A session grant (or a still-unconsumed `once` grant) must not prompt
    // again; `check` is the only non-consuming way to find out.
    if broker.is_approved(&resolved, WriteOp::Overwrite)
        || broker.is_approved(&resolved, WriteOp::Create)
    {
        broker
            .write(&resolved, data)
            .map_err(|error| format!("broker write failed: {error}"))?;
        return Ok(Outcome::HandledThroughBroker);
    }

    let request = PermissionRequest::new(tool_call_id, verb, raw_path, &resolved, data.len());
    match approver.ask(&request) {
        Answer::Deny => Err(format!(
            "{} of {} was denied; approve interactively or add it to sandbox.writable",
            verb,
            resolved.display()
        )),
        Answer::Allow { scope, recursive } => {
            broker
                .approve(
                    &resolved,
                    &[WriteOp::Create, WriteOp::Overwrite],
                    scope,
                    recursive,
                )
                .map_err(|error| format!("cannot record the approval: {error}"))?;
            broker
                .write(&resolved, data)
                .map_err(|error| format!("broker write failed: {error}"))?;
            Ok(Outcome::HandledThroughBroker)
        }
    }
}

/// Parse `write` tool parameters.
pub fn parse_write(params: &Value) -> Result<(String, String), String> {
    let path = params
        .get("path")
        .and_then(Value::as_str)
        .filter(|path| !path.is_empty())
        .ok_or("write requires a nonempty string `path`")?;
    let content = params
        .get("content")
        .and_then(Value::as_str)
        .ok_or("write requires a string `content`")?;
    Ok((path.to_string(), content.to_string()))
}

/// Parse `edit` tool parameters into `(path, replacements)`.
///
/// Accepts the current `edits: [{oldText,newText}]` shape and the legacy
/// top-level `oldText` / `newText` pair.
pub fn parse_edits(params: &Value) -> Result<(String, Vec<(String, String)>), String> {
    let path = params
        .get("path")
        .and_then(Value::as_str)
        .filter(|path| !path.is_empty())
        .ok_or("edit requires a nonempty string `path`")?;
    let mut edits = Vec::new();
    if let Some(array) = params.get("edits").and_then(Value::as_array) {
        for edit in array {
            let old = edit
                .get("oldText")
                .and_then(Value::as_str)
                .ok_or("each edit requires a string `oldText`")?;
            let new = edit
                .get("newText")
                .and_then(Value::as_str)
                .ok_or("each edit requires a string `newText`")?;
            edits.push((old.to_string(), new.to_string()));
        }
    } else {
        let old = params
            .get("oldText")
            .and_then(Value::as_str)
            .ok_or("edit requires `edits` or `oldText`/`newText`")?;
        let new = params
            .get("newText")
            .and_then(Value::as_str)
            .ok_or("edit requires `edits` or `oldText`/`newText`")?;
        edits.push((old.to_string(), new.to_string()));
    }
    if edits.is_empty() {
        return Err("edit requires at least one replacement".to_string());
    }
    Ok((path.to_string(), edits))
}

/// Apply exact-text replacements; each `oldText` must match exactly once.
pub fn apply_edits(original: &str, edits: &[(String, String)]) -> Result<String, String> {
    let mut content = original.to_string();
    for (old, new) in edits {
        if old.is_empty() {
            return Err("edit oldText must not be empty".to_string());
        }
        let matches = content.matches(old).count();
        if matches != 1 {
            return Err(format!(
                "oldText must match exactly once in the file (found {matches})"
            ));
        }
        content = content.replacen(old, new, 1);
    }
    Ok(content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rpi_sandbox_core::{ApprovalSettings, PathRule, SandboxMode};
    use std::cell::RefCell;
    use std::path::PathBuf;

    struct FixedApprover(Answer);

    impl Approver for FixedApprover {
        fn ask(&self, _request: &PermissionRequest) -> Answer {
            self.0
        }
    }

    #[derive(Default)]
    struct RecordingBroker {
        approved: RefCell<Vec<(PathBuf, ApprovalScope, bool)>>,
        written: RefCell<Vec<(PathBuf, Vec<u8>)>>,
        preapproved: bool,
        fail: bool,
    }

    impl BrokerOps for RecordingBroker {
        fn approve(
            &self,
            path: &Path,
            _operations: &[WriteOp],
            scope: ApprovalScope,
            recursive: bool,
        ) -> Result<(), String> {
            self.approved
                .borrow_mut()
                .push((path.to_path_buf(), scope, recursive));
            Ok(())
        }

        fn write(&self, path: &Path, data: &[u8]) -> Result<(), String> {
            if self.fail {
                return Err("disk full".to_string());
            }
            self.written
                .borrow_mut()
                .push((path.to_path_buf(), data.to_vec()));
            Ok(())
        }

        fn is_approved(&self, _path: &Path, _operation: WriteOp) -> bool {
            self.preapproved
        }
    }

    fn policy(writable: &[&str], protected: &[&str]) -> SandboxPolicy {
        SandboxPolicy {
            enabled: true,
            mode: SandboxMode::Auto,
            writable: writable
                .iter()
                .map(|p| PathRule::Dir(PathBuf::from(p)))
                .collect(),
            protected: protected
                .iter()
                .map(|p| PathRule::Dir(PathBuf::from(p)))
                .collect(),
            allow_file_writes: Vec::new(),
            approval: ApprovalSettings::default(),
            audit_log: None,
        }
    }

    #[test]
    fn in_policy_writes_are_left_to_the_builtin_tool() {
        let broker = RecordingBroker::default();
        let approver = FixedApprover(Answer::Deny);
        let outcome = handle_write(
            &policy(&["/work"], &[]),
            true,
            Path::new("/work"),
            &approver,
            Some(&broker),
            "tool-1",
            "write",
            "/work/a.txt",
            b"x",
        )
        .unwrap();
        assert_eq!(outcome, Outcome::AllowTool);
        assert!(broker.written.borrow().is_empty());
    }

    #[test]
    fn protected_paths_are_never_approvable() {
        let broker = RecordingBroker::default();
        let approver = FixedApprover(Answer::Allow {
            scope: ApprovalScope::Session,
            recursive: false,
        });
        let error = handle_write(
            &policy(&["/work"], &["/work/secrets"]),
            true,
            Path::new("/work"),
            &approver,
            Some(&broker),
            "tool-1",
            "write",
            "/work/secrets/key",
            b"x",
        )
        .unwrap_err();
        assert!(error.contains("protected"));
        assert!(broker.written.borrow().is_empty());
    }

    #[test]
    fn unisolated_out_of_policy_writes_are_blocked_with_instructions() {
        let broker = RecordingBroker::default();
        let approver = FixedApprover(Answer::Allow {
            scope: ApprovalScope::Session,
            recursive: false,
        });
        let error = handle_write(
            &policy(&["/work"], &[]),
            false,
            Path::new("/work"),
            &approver,
            Some(&broker),
            "tool-1",
            "write",
            "/etc/passwd",
            b"x",
        )
        .unwrap_err();
        assert!(error.contains("NOT isolated"));
        assert!(broker.written.borrow().is_empty());
    }

    #[test]
    fn denial_does_not_write() {
        let broker = RecordingBroker::default();
        let approver = FixedApprover(Answer::Deny);
        let error = handle_write(
            &policy(&["/work"], &[]),
            true,
            Path::new("/work"),
            &approver,
            Some(&broker),
            "tool-1",
            "write",
            "/etc/passwd",
            b"x",
        )
        .unwrap_err();
        assert!(error.contains("denied"));
        assert!(broker.written.borrow().is_empty());
    }

    #[test]
    fn approval_routes_the_write_through_the_broker() {
        let broker = RecordingBroker::default();
        let approver = FixedApprover(Answer::Allow {
            scope: ApprovalScope::Once,
            recursive: true,
        });
        let outcome = handle_write(
            &policy(&["/work"], &[]),
            true,
            Path::new("/work"),
            &approver,
            Some(&broker),
            "tool-1",
            "write",
            "/etc/example.conf",
            b"data",
        )
        .unwrap();
        assert_eq!(outcome, Outcome::HandledThroughBroker);
        assert_eq!(
            broker.approved.borrow().as_slice(),
            [(
                PathBuf::from("/etc/example.conf"),
                ApprovalScope::Once,
                true
            )]
        );
        assert_eq!(
            broker.written.borrow().as_slice(),
            [(PathBuf::from("/etc/example.conf"), b"data".to_vec())]
        );
    }

    #[test]
    fn existing_session_approval_skips_the_prompt() {
        let broker = RecordingBroker {
            preapproved: true,
            ..RecordingBroker::default()
        };
        // A denying approver must not even be consulted.
        let approver = FixedApprover(Answer::Deny);
        let outcome = handle_write(
            &policy(&["/work"], &[]),
            true,
            Path::new("/work"),
            &approver,
            Some(&broker),
            "tool-1",
            "write",
            "/etc/example.conf",
            b"data",
        )
        .unwrap();
        assert_eq!(outcome, Outcome::HandledThroughBroker);
        assert!(broker.approved.borrow().is_empty());
        assert_eq!(broker.written.borrow().len(), 1);
    }

    #[test]
    fn missing_broker_denies() {
        let approver = FixedApprover(Answer::Allow {
            scope: ApprovalScope::Session,
            recursive: false,
        });
        let error = handle_write(
            &policy(&["/work"], &[]),
            true,
            Path::new("/work"),
            &approver,
            None,
            "tool-1",
            "write",
            "/etc/passwd",
            b"x",
        )
        .unwrap_err();
        assert!(error.contains("broker is unavailable"));
    }

    #[test]
    fn broker_failure_is_reported() {
        let broker = RecordingBroker {
            fail: true,
            ..RecordingBroker::default()
        };
        let approver = FixedApprover(Answer::Allow {
            scope: ApprovalScope::Session,
            recursive: false,
        });
        let error = handle_write(
            &policy(&["/work"], &[]),
            true,
            Path::new("/work"),
            &approver,
            Some(&broker),
            "tool-1",
            "write",
            "/etc/passwd",
            b"x",
        )
        .unwrap_err();
        assert!(error.contains("disk full"));
    }

    #[test]
    fn parses_write_and_edit_parameters() {
        let (path, content) =
            parse_write(&serde_json::json!({"path":"a.txt","content":"hi"})).unwrap();
        assert_eq!(path, "a.txt");
        assert_eq!(content, "hi");
        assert!(parse_write(&serde_json::json!({"path":"a.txt"})).is_err());

        let (path, edits) = parse_edits(&serde_json::json!({
            "path":"a.txt",
            "edits":[{"oldText":"a","newText":"b"}]
        }))
        .unwrap();
        assert_eq!(path, "a.txt");
        assert_eq!(edits, [("a".to_string(), "b".to_string())]);

        let (_, legacy) = parse_edits(&serde_json::json!({
            "path":"a.txt","oldText":"a","newText":"b"
        }))
        .unwrap();
        assert_eq!(legacy.len(), 1);
        assert!(parse_edits(&serde_json::json!({"path":"a.txt","edits":[]})).is_err());
    }

    #[test]
    fn edits_must_match_exactly_once() {
        assert_eq!(
            apply_edits("hello world", &[("world".into(), "there".into())]).unwrap(),
            "hello there"
        );
        assert!(apply_edits("aaa", &[("a".into(), "b".into())]).is_err());
        assert!(apply_edits("abc", &[("z".into(), "b".into())]).is_err());
        assert!(apply_edits("abc", &[("".into(), "b".into())]).is_err());
    }
}
