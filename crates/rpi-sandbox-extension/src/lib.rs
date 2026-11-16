//! `rpi-sandbox` extension.
//!
//! The extension owns policy, approvals, audit (through the broker), commands,
//! and status. It **never** creates the kernel boundary: that only happens in
//! the launcher before `exec`. Without `RPI_SANDBOX_ACTIVE` it reports
//! "not isolated" and gates tools advisory-only.
//!
//! Out-of-policy writes are approved through a `UiDialog` permission prompt and
//! executed by the broker; the ToolCall handler then vetoes the built-in tool so
//! it cannot fail with `EACCES`.

mod config;
mod dialog;
mod gate;
mod host;
mod prompt;

use std::path::PathBuf;
use std::sync::OnceLock;

use rpi_plugin_sdk::events::{EventView, ToolCall};
use rpi_plugin_sdk::{
    callbacks::Output, EventTag, PluginApi, StablePluginEvent, StbString, StbStringRef,
    EVENT_HANDLER_ABORT,
};
use rpi_sandbox_core::{ApprovalScope, BrokerClient, WriteOp};
use serde_json::Value;

use crate::config::Config;
use crate::gate::{BrokerOps, Outcome, UiApprover};

/// Crate name used in diagnostics.
pub const CRATE_NAME: &str = "rpi-sandbox-extension";

struct State {
    config: Config,
    backend: Option<String>,
    /// Block appended to the system prompt, rendered once at registration.
    prompt_block: String,
    /// Whether the host accepted the `before_agent_start` transform.
    prompt_hint: bool,
}

static STATE: OnceLock<State> = OnceLock::new();
static BROKER: OnceLock<BrokerClient> = OnceLock::new();

/// Adapter from the protocol client to the gate's broker surface.
struct ClientBroker<'a>(&'a BrokerClient);

impl BrokerOps for ClientBroker<'_> {
    fn approve(
        &self,
        path: &std::path::Path,
        operations: &[WriteOp],
        scope: ApprovalScope,
        recursive: bool,
    ) -> Result<(), String> {
        self.0
            .approve(path, operations, scope, recursive)
            .map_err(|error| error.to_string())
    }

    fn is_approved(&self, path: &std::path::Path, operation: WriteOp) -> bool {
        self.0.is_approved(path, operation)
    }

    fn write(&self, path: &std::path::Path, data: &[u8]) -> Result<(), String> {
        self.0.write(path, data).map_err(|error| error.to_string())
    }
}

rpi_plugin_sdk::export_plugin!(|api| {
    host::install(api);

    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let config = Config::from_env(&cwd);

    if !config.isolated {
        eprintln!(
            "warning: rpi-sandbox: current process is NOT isolated; start rpi through \
             rpi-sandbox for a kernel boundary (tool gating is advisory only)"
        );
    }

    let mut backend = None;
    if config.isolated {
        match config.socket.as_deref() {
            Some(socket) => match BrokerClient::connect(socket) {
                Ok(client) => {
                    match client.hello(CRATE_NAME, env!("CARGO_PKG_VERSION")) {
                        Ok(hello) => backend = hello.sandbox,
                        Err(error) => {
                            eprintln!("warning: sandbox: broker handshake failed: {error}")
                        }
                    }
                    let _ = BROKER.set(client);
                }
                Err(error) => {
                    eprintln!("warning: sandbox: approval broker unavailable: {error}");
                }
            },
            None => {
                eprintln!("warning: sandbox: no broker socket; out-of-policy writes will be denied")
            }
        }
    }

    let prompt_block = prompt::render(&config.policy, config.isolated, backend.as_deref());
    let prompt_hint = register_prompt(&api);
    let _ = STATE.set(State {
        config,
        backend,
        prompt_block,
        prompt_hint,
    });

    let Some(register_event) = api.register_event_handler else {
        eprintln!("error: sandbox: host does not support event handlers");
        return 1;
    };
    let _ = register_event(EventTag::ToolCall, on_tool_call, std::ptr::null_mut());
    let _ = register_event(
        EventTag::SessionStart,
        on_session_start,
        std::ptr::null_mut(),
    );

    if let Some(register_command) = api.register_command {
        let _ = register_command(
            StbStringRef::from_str("sandbox"),
            StbStringRef::from_str("Show or revoke filesystem sandbox approvals"),
            on_sandbox_command,
        );
    }

    0
});

fn state() -> Option<&'static State> {
    STATE.get()
}

/// Register the system-prompt transform.
///
/// The slot is appended to `PluginApi`, so an older host may hand over a
/// shorter struct: check `struct_size` before reading it. Returns `false` when
/// the hint is unavailable, which `/sandbox` reports.
fn register_prompt(api: &PluginApi) -> bool {
    let end =
        std::mem::offset_of!(PluginApi, register_before_agent_start) + std::mem::size_of::<usize>();
    if (api.struct_size as usize) < end {
        eprintln!(
            "warning: sandbox: host predates the prompt transform; the model will not be \
             told about the sandbox"
        );
        return false;
    }
    let Some(register) = api.register_before_agent_start else {
        return false;
    };
    let rc = register(
        on_before_agent_start,
        rpi_plugin_sdk::callbacks::free_string,
        std::ptr::null_mut(),
    );
    if rc != 0 {
        eprintln!("warning: sandbox: host rejected the prompt transform (rc={rc})");
        return false;
    }
    true
}

/// Append the sandbox block to the prompt the host is about to send.
extern "C" fn on_before_agent_start(
    event_json: StbStringRef,
    out: *mut StbString,
    _user_data: *mut std::ffi::c_void,
) -> i32 {
    rpi_plugin_sdk::guard_or(1, || {
        let Some(state) = state() else {
            return 0;
        };
        // SAFETY: the host keeps the borrowed envelope alive for this call.
        let envelope = unsafe { event_json.as_str() };
        let Some(payload) = prompt_patch(envelope, &state.prompt_block) else {
            return 0;
        };
        // SAFETY: `out` is the host-provided output slot, valid for this call.
        let mut output = unsafe { Output::from_raw(out) };
        i32::from(!output.write(payload))
    })
}

/// Build the `{"systemPrompt": ...}` patch for one `before_agent_start`
/// envelope.
///
/// Returns `None` when the envelope carries no prompt (the transform would
/// otherwise replace the host's whole system prompt) or when the block is
/// already present.
fn prompt_patch(envelope: &str, block: &str) -> Option<String> {
    let parsed: Value = serde_json::from_str(envelope).ok()?;
    let current = parsed.get("systemPrompt")?.as_str()?;
    let next = prompt::append_once(current, block)?;
    Some(serde_json::json!({ "systemPrompt": next }).to_string())
}

extern "C" fn on_session_start(
    _event: StablePluginEvent,
    _user_data: *mut std::ffi::c_void,
) -> i32 {
    rpi_plugin_sdk::guard_or(1, || {
        if let Some(state) = state() {
            host::set_status("sandbox", &state.config.status_label());
        }
        0
    })
}

extern "C" fn on_tool_call(event: StablePluginEvent, _user_data: *mut std::ffi::c_void) -> i32 {
    rpi_plugin_sdk::guard_or(1, || {
        // SAFETY: the host keeps the event payload alive for this call.
        let view = unsafe { EventView::from_raw(&event) };
        let Some(call) = view.tool_call() else {
            return 0;
        };
        match call.tool_name.as_str() {
            // The whole process is already confined, so shell commands inherit
            // the same boundary. v1 has no command-level policy.
            "bash" => 0,
            "write" => handle_write_call(&call),
            "edit" => handle_edit_call(&call),
            _ => 0,
        }
    })
}

fn handle_write_call(call: &ToolCall) -> i32 {
    let parsed: Value = match serde_json::from_str(&call.params) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("sandbox: cannot parse write parameters: {error}");
            return 0;
        }
    };
    let (path, content) = match gate::parse_write(&parsed) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("sandbox: {error}");
            return 0;
        }
    };
    let state = match state() {
        Some(state) => state,
        None => return 0,
    };
    // In-policy writes are permitted by the kernel; leave them to the built-in
    // tool (which also preserves truncation/queue semantics).
    let resolved = config::resolve_tool_path(&state.config.cwd, &path);
    if state.config.policy.is_writable(&resolved) {
        return 0;
    }

    let broker = BROKER.get().map(ClientBroker);
    let approver = UiApprover {
        host: &host::UiDialogBridge,
    };
    finish(gate::handle_write(
        &state.config.policy,
        state.config.isolated,
        &state.config.cwd,
        &approver,
        broker.as_ref().map(|broker| broker as &dyn BrokerOps),
        &call.tool_call_id,
        "write",
        &path,
        content.as_bytes(),
    ))
}

fn handle_edit_call(call: &ToolCall) -> i32 {
    let parsed: Value = match serde_json::from_str(&call.params) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("sandbox: cannot parse edit parameters: {error}");
            return 0;
        }
    };
    let (path, edits) = match gate::parse_edits(&parsed) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("sandbox: {error}");
            return 0;
        }
    };
    let state = match state() {
        Some(state) => state,
        None => return 0,
    };
    let resolved = config::resolve_tool_path(&state.config.cwd, &path);
    if state.config.policy.is_writable(&resolved) {
        return 0;
    }
    if state.config.policy.classify(&resolved) == rpi_sandbox_core::Access::Protected {
        return finish(Err(format!(
            "{} is protected by sandbox policy and cannot be written",
            resolved.display()
        )));
    }

    let original = match std::fs::read_to_string(&resolved) {
        Ok(content) => content,
        Err(error) => {
            return finish(Err(format!(
                "cannot read {} before editing: {error}",
                resolved.display()
            )))
        }
    };
    let edited = match gate::apply_edits(&original, &edits) {
        Ok(content) => content,
        Err(error) => return finish(Err(error)),
    };

    let broker = BROKER.get().map(ClientBroker);
    let approver = UiApprover {
        host: &host::UiDialogBridge,
    };
    finish(gate::handle_write(
        &state.config.policy,
        state.config.isolated,
        &state.config.cwd,
        &approver,
        broker.as_ref().map(|broker| broker as &dyn BrokerOps),
        &call.tool_call_id,
        "edit",
        &path,
        edited.as_bytes(),
    ))
}

fn finish(outcome: Result<Outcome, String>) -> i32 {
    match outcome {
        Ok(Outcome::AllowTool) => 0,
        Ok(Outcome::HandledThroughBroker) => {
            host::set_status("sandbox", "🔒 sandbox (broker write)");
            EVENT_HANDLER_ABORT
        }
        Err(error) => {
            eprintln!("sandbox: {error}");
            host::set_status("sandbox", &format!("⛔ {error}"));
            EVENT_HANDLER_ABORT
        }
    }
}

extern "C" fn on_sandbox_command(
    args_json: StbStringRef,
    out: *mut StbString,
    _user_data: *mut std::ffi::c_void,
) -> i32 {
    rpi_plugin_sdk::guard_or(1, || {
        // SAFETY: the host keeps the borrowed args alive for this call.
        let args = unsafe { args_json.as_str() };
        let text = run_command(args);
        let payload = serde_json::json!({"kind": "message", "text": text}).to_string();
        // SAFETY: `out` is the host-provided output slot, valid for this call.
        let mut output = unsafe { Output::from_raw(out) };
        i32::from(!output.write(payload))
    })
}

fn run_command(args_json: &str) -> String {
    let Some(state) = state() else {
        return "sandbox extension is not initialized".to_string();
    };
    let parsed: Value = serde_json::from_str(args_json).unwrap_or(Value::Null);
    let args = parsed
        .get("args")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if let Some(rest) = args.strip_prefix("revoke") {
        let rest = rest.trim();
        if rest.is_empty() {
            return "usage: /sandbox revoke <path>".to_string();
        }
        let path = config::resolve_tool_path(&state.config.cwd, rest);
        return match BROKER.get() {
            Some(broker) => match broker.revoke(&path, true) {
                Ok(()) => format!("revoked sandbox approvals for {}", path.display()),
                Err(error) => format!("cannot revoke {}: {error}", path.display()),
            },
            None => "approval broker is unavailable".to_string(),
        };
    }
    let mut description = state.config.describe();
    if let Some(backend) = &state.backend {
        description.push_str(&format!("\nbackend: {backend}"));
    }
    description.push_str(&format!(
        "\nmodel hint: {}",
        if state.prompt_hint {
            "appended to the system prompt"
        } else {
            "unsupported by this host"
        }
    ));
    description.push_str("\n\ncommands: /sandbox, /sandbox revoke <path>");
    description
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gate::Approver;

    use rpi_sandbox_core::{PathRule, SandboxMode, SandboxPolicy};

    struct Allow;

    impl Approver for Allow {
        fn ask(&self, _request: &dialog::PermissionRequest) -> dialog::Answer {
            dialog::Answer::Allow {
                scope: ApprovalScope::Session,
                recursive: false,
            }
        }
    }

    fn policy(writable: &str) -> SandboxPolicy {
        SandboxPolicy {
            enabled: true,
            mode: SandboxMode::Auto,
            writable: vec![PathRule::Dir(PathBuf::from(writable))],
            protected: Vec::new(),
            allow_file_writes: Vec::new(),
            approval: rpi_sandbox_core::ApprovalSettings::default(),
            audit_log: None,
        }
    }

    #[test]
    fn prompt_patch_appends_to_the_host_prompt() {
        let block = prompt::render(&policy("/work"), true, Some("landlock"));
        let envelope = serde_json::json!({
            "prompt": "hello",
            "systemPrompt": "You are rpi."
        })
        .to_string();
        let patch = prompt_patch(&envelope, &block).unwrap();
        let parsed: Value = serde_json::from_str(&patch).unwrap();
        let prompt = parsed["systemPrompt"].as_str().unwrap();
        assert!(prompt.starts_with("You are rpi.\n\n## Sandbox"));
        assert!(prompt.contains("- /work"));
        assert!(prompt.contains("landlock"));
    }

    #[test]
    fn prompt_patch_declines_without_an_existing_prompt() {
        let block = prompt::render(&policy("/work"), true, None);
        assert!(prompt_patch("{}", &block).is_none());
        assert!(prompt_patch(r#"{"systemPrompt": ""}"#, &block).is_none());
        assert!(prompt_patch(r#"{"systemPrompt": 42}"#, &block).is_none());
        assert!(prompt_patch("not json", &block).is_none());
    }

    #[test]
    fn prompt_patch_is_idempotent() {
        let block = prompt::render(&policy("/work"), true, None);
        let first = prompt_patch(
            &serde_json::json!({"systemPrompt": "You are rpi."}).to_string(),
            &block,
        )
        .unwrap();
        let envelope: Value = serde_json::from_str(&first).unwrap();
        let second = serde_json::json!({
            "systemPrompt": envelope["systemPrompt"]
        })
        .to_string();
        assert!(prompt_patch(&second, &block).is_none());
    }

    #[test]
    fn out_of_policy_write_reaches_the_real_broker() {
        use rpi_sandbox_core::{serve, BrokerConfig, Listener};
        use std::io::BufReader;

        let dir = tempfile::tempdir().unwrap();
        let listener = Listener::bind().unwrap();
        let endpoint = listener.name().to_path_buf();
        let server = std::thread::spawn(move || {
            let conn = listener.accept().unwrap();
            let reader = BufReader::new(conn.try_clone().unwrap());
            serve(reader, conn, BrokerConfig::default()).unwrap();
        });

        let client = BrokerClient::connect(&endpoint).unwrap();
        let broker = ClientBroker(&client);
        let target = dir.path().join("approved.txt");
        let outcome = gate::handle_write(
            &policy("/work"),
            true,
            std::path::Path::new("/work"),
            &Allow,
            Some(&broker as &dyn BrokerOps),
            "tool-1",
            "write",
            target.to_str().unwrap(),
            b"from the extension",
        )
        .unwrap();
        assert_eq!(outcome, Outcome::HandledThroughBroker);
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "from the extension"
        );
        drop(client);
        server.join().unwrap();
    }
}
