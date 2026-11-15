//! Permission dialogs.
//!
//! The extension only uses the public `UiDialog` runtime action with
//! `purpose: "permission"` and explicit `allow_once` / `allow_always` /
//! `reject_once` semantics. A second, explicit prompt upgrades a session grant
//! to the containing directory, so directory scope is never implied.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rpi_sandbox_core::ApprovalScope;
use serde_json::{json, Value};

/// Default time a tool call waits for a human (the host dialog timeout also
/// applies; an expired prompt is treated as a denial).
pub const APPROVAL_TIMEOUT: Duration = Duration::from_secs(300);

/// Poll interval while waiting for the UI to answer.
const POLL_INTERVAL: Duration = Duration::from_millis(40);

/// UI runtime action used by [`DialogHost`] implementations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DialogAction {
    /// `open`: enqueue a request.
    Open,
    /// `poll`: read the current answer.
    Poll,
    /// `cancel`: withdraw an unanswered request.
    Cancel,
}

/// Transport used to talk to the host UI.
pub trait DialogHost {
    /// Invoke the `UiDialog` runtime action.
    fn dialog(&self, action: DialogAction, args: &Value) -> Result<Value, String>;
}

/// One permission prompt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PermissionRequest {
    /// Unique dialog id.
    pub request_id: String,
    /// Tool call the prompt belongs to.
    pub tool_call_id: String,
    /// Verb shown to the user (`write`, `edit`, ...).
    pub verb: String,
    /// Raw path supplied by the model.
    pub raw_path: String,
    /// Absolute, resolved path.
    pub resolved: PathBuf,
    /// Byte count when the operation carries data.
    pub bytes: Option<u64>,
}

impl PermissionRequest {
    /// Build a request with a fresh id.
    pub fn new(
        tool_call_id: &str,
        verb: &str,
        raw_path: &str,
        resolved: &Path,
        bytes: usize,
    ) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        Self {
            request_id: format!(
                "sandbox:{}:{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ),
            tool_call_id: tool_call_id.to_string(),
            verb: verb.to_string(),
            raw_path: raw_path.to_string(),
            resolved: resolved.to_path_buf(),
            bytes: Some(bytes as u64),
        }
    }

    fn question(&self) -> String {
        let mut text = format!("Allow {} of {}?", self.verb, self.resolved.display());
        if self.raw_path != self.resolved.to_string_lossy() {
            text.push_str(&format!("\nrequested: {}", self.raw_path));
        }
        if let Some(bytes) = self.bytes {
            text.push_str(&format!("\n{bytes} bytes"));
        }
        text
    }
}

/// User's decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    /// Allow with the chosen scope; `recursive` covers the containing directory.
    Allow {
        /// `once` or `session`.
        scope: ApprovalScope,
        /// Whether the whole directory was approved.
        recursive: bool,
    },
    /// Deny the request.
    Deny,
}

/// The `open` envelope for one request.
pub fn envelope(request: &PermissionRequest) -> Value {
    json!({
        "op": "open",
        "requestId": request.request_id,
        "toolCallId": request.tool_call_id,
        "ui": {
            "purpose": "permission",
            "kind": "confirm",
            "header": "Filesystem sandbox",
            "question": request.question(),
            "options": [
                {"title": "Allow once", "permission": "allow_once"},
                {"title": "Allow for this session", "permission": "allow_always"},
                {"title": "Deny", "permission": "reject_once"}
            ]
        }
    })
}

/// Follow-up envelope that offers to widen a session grant to the directory.
pub fn directory_envelope(request_id: &str, tool_call_id: &str, resolved: &Path) -> Value {
    let directory = resolved.parent().unwrap_or(resolved);
    json!({
        "op": "open",
        "requestId": format!("{request_id}:dir"),
        "toolCallId": tool_call_id,
        "ui": {
            "purpose": "permission",
            "kind": "confirm",
            "header": "Filesystem sandbox",
            "question": format!(
                "Also allow the whole directory {} for this session?",
                directory.display()
            ),
            "options": [
                {"title": "Allow this directory", "permission": "allow_always"},
                {"title": "Only this file", "permission": "reject_once"}
            ]
        }
    })
}

/// Parse the selected permission from a dialog answer.
pub fn parse_answer(answer: &Value) -> Answer {
    let permission = answer.get("permission").and_then(Value::as_str);
    match permission {
        Some("allow_once") => Answer::Allow {
            scope: ApprovalScope::Once,
            recursive: false,
        },
        Some("allow_always") => Answer::Allow {
            scope: ApprovalScope::Session,
            recursive: false,
        },
        _ => Answer::Deny,
    }
}

/// Ask the user, or deny when no interactive UI is available.
///
/// A headless run fails the `open` call with "requires an interactive UI";
/// that, a cancel, a timeout, or any transport error denies the request.
pub fn ask(host: &dyn DialogHost, request: &PermissionRequest) -> Answer {
    let opened = match host.dialog(DialogAction::Open, &envelope(request)) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("sandbox: approval denied ({error})");
            return Answer::Deny;
        }
    };
    let answer = match wait_for_answer(host, request, &opened) {
        Some(answer) => answer,
        None => return Answer::Deny,
    };
    let Answer::Allow {
        scope: ApprovalScope::Session,
        recursive: false,
    } = answer
    else {
        return answer;
    };
    ask_directory(host, request)
}

fn ask_directory(host: &dyn DialogHost, request: &PermissionRequest) -> Answer {
    let envelope = directory_envelope(
        &request.request_id,
        &request.tool_call_id,
        &request.resolved,
    );
    let opened = match host.dialog(DialogAction::Open, &envelope) {
        Ok(value) => value,
        Err(_) => {
            return Answer::Allow {
                scope: ApprovalScope::Session,
                recursive: false,
            }
        }
    };
    let Some(answer) = wait_for_answer(host, request, &opened) else {
        return Answer::Allow {
            scope: ApprovalScope::Session,
            recursive: false,
        };
    };
    match answer {
        Answer::Allow {
            scope: ApprovalScope::Session,
            ..
        } => Answer::Allow {
            scope: ApprovalScope::Session,
            recursive: true,
        },
        _ => Answer::Allow {
            scope: ApprovalScope::Session,
            recursive: false,
        },
    }
}

fn wait_for_answer(
    host: &dyn DialogHost,
    request: &PermissionRequest,
    opened: &Value,
) -> Option<Answer> {
    if let Some(answer) = answered(opened) {
        return Some(answer);
    }
    let deadline = Instant::now() + APPROVAL_TIMEOUT;
    loop {
        if Instant::now() >= deadline {
            let _ = host.dialog(
                DialogAction::Cancel,
                &json!({"op": "cancel", "requestId": request.request_id}),
            );
            return None;
        }
        std::thread::sleep(POLL_INTERVAL);
        let status = host
            .dialog(
                DialogAction::Poll,
                &json!({"op": "poll", "requestId": request.request_id}),
            )
            .ok()?;
        match status.get("status").and_then(Value::as_str) {
            Some("answered") => {
                return Some(parse_answer(status.get("answer").unwrap_or(&Value::Null)))
            }
            Some("cancelled") => return None,
            Some("pending") => continue,
            _ => return None,
        }
    }
}

fn answered(value: &Value) -> Option<Answer> {
    match value.get("status").and_then(Value::as_str) {
        Some("answered") => Some(parse_answer(value.get("answer").unwrap_or(&Value::Null))),
        Some("cancelled") => None,
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    /// Fake UI that returns queued statuses.
    struct FakeHost {
        answers: Mutex<VecDeque<Result<Value, String>>>,
        opened: Mutex<Vec<Value>>,
    }

    impl FakeHost {
        fn new(answers: Vec<Result<Value, String>>) -> Self {
            Self {
                answers: Mutex::new(answers.into()),
                opened: Mutex::new(Vec::new()),
            }
        }
    }

    impl DialogHost for FakeHost {
        fn dialog(&self, action: DialogAction, args: &Value) -> Result<Value, String> {
            match action {
                DialogAction::Open => {
                    self.opened.lock().unwrap().push(args.clone());
                    Ok(json!({"status":"pending"}))
                }
                DialogAction::Poll => self
                    .answers
                    .lock()
                    .unwrap()
                    .pop_front()
                    .unwrap_or(Err("no more answers".to_string())),
                DialogAction::Cancel => Ok(json!({"status":"cancelled"})),
            }
        }
    }

    fn request() -> PermissionRequest {
        PermissionRequest::new(
            "tool-1",
            "write",
            "/tmp/out/file.txt",
            Path::new("/tmp/out/file.txt"),
            3,
        )
    }

    #[test]
    fn envelope_is_a_valid_permission_dialog() {
        let value = envelope(&request());
        rpi_plugin_sdk::dialogs::validate(value.get("ui").unwrap(), Some("tool-1")).unwrap();
        assert_eq!(value["ui"]["purpose"], "permission");
        assert_eq!(value["ui"]["options"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn directory_envelope_is_a_valid_permission_dialog() {
        let value = directory_envelope("r1", "tool-1", Path::new("/tmp/out/file.txt"));
        rpi_plugin_sdk::dialogs::validate(value.get("ui").unwrap(), Some("tool-1")).unwrap();
        assert!(value["ui"]["question"]
            .as_str()
            .unwrap()
            .contains("/tmp/out"));
    }

    #[test]
    fn answers_map_to_scopes() {
        assert_eq!(
            parse_answer(&json!({"permission":"allow_once"})),
            Answer::Allow {
                scope: ApprovalScope::Once,
                recursive: false
            }
        );
        assert_eq!(
            parse_answer(&json!({"permission":"allow_always"})),
            Answer::Allow {
                scope: ApprovalScope::Session,
                recursive: false
            }
        );
        assert_eq!(
            parse_answer(&json!({"permission":"reject_once"})),
            Answer::Deny
        );
        assert_eq!(parse_answer(&json!({})), Answer::Deny);
    }

    #[test]
    fn headless_open_failure_denies() {
        struct Headless;
        impl DialogHost for Headless {
            fn dialog(&self, _action: DialogAction, _args: &Value) -> Result<Value, String> {
                Err("ask_user requires an interactive UI".to_string())
            }
        }
        assert_eq!(ask(&Headless, &request()), Answer::Deny);
    }

    #[test]
    fn session_grants_get_an_explicit_directory_follow_up() {
        let host = FakeHost::new(vec![
            Ok(json!({"status":"answered","answer":{"permission":"allow_always"}})),
            Ok(json!({"status":"answered","answer":{"permission":"allow_always"}})),
        ]);
        assert_eq!(
            ask(&host, &request()),
            Answer::Allow {
                scope: ApprovalScope::Session,
                recursive: true
            }
        );
        assert_eq!(host.opened.lock().unwrap().len(), 2);
    }

    #[test]
    fn declining_the_directory_follow_up_keeps_the_file_scope() {
        let host = FakeHost::new(vec![
            Ok(json!({"status":"answered","answer":{"permission":"allow_always"}})),
            Ok(json!({"status":"answered","answer":{"permission":"reject_once"}})),
        ]);
        assert_eq!(
            ask(&host, &request()),
            Answer::Allow {
                scope: ApprovalScope::Session,
                recursive: false
            }
        );
    }

    #[test]
    fn cancelled_dialogs_deny() {
        let host = FakeHost::new(vec![Ok(json!({"status":"cancelled"}))]);
        assert_eq!(ask(&host, &request()), Answer::Deny);
    }
}
