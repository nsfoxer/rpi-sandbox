//! Model-facing explanation of the sandbox.
//!
//! Landlock refuses a denied write with `EACCES`, which looks exactly like a
//! normal permission problem, and the host never hands a failed tool result to
//! a `tool_result` transform. The `before_agent_start` system-prompt transform
//! is the only channel that reaches the model *before* it starts probing
//! mounts, ownership, ACLs, or alternate paths.
//!
//! The block states the policy, not the enforcement holes: a model does not
//! need to be told which protected paths a direct shell write could still
//! reach.

use rpi_sandbox_core::SandboxPolicy;

/// Heading that makes [`append_once`] idempotent across `/reload`.
pub const MARKER: &str = "## Sandbox (rpi-sandbox)";

/// Writable roots listed before the rest are summarized.
const MAX_ROOTS: usize = 12;

/// What a denial looks like and what it means.
const DENIAL_NOTICE: &str = "\
All other paths are read-only. A denied write appears as `EACCES` (\"Permission
denied\" / \"权限不够\") in `bash` output. That is the sandbox, not a filesystem,
mount, ownership, or ACL problem: do not investigate it, and do not try to work
around it (`sudo`, `chmod`, alternate paths, symlinks, `/proc/*/root`, or
repeating the same write).";

/// How an out-of-policy write can still succeed.
const APPROVAL_NOTICE: &str = "\
To write outside these roots, use the `write` or `edit` tool; the sandbox can ask
the user and apply an approved write through its broker. `bash` cannot request
approval, so a denied shell write stays denied. If the user declines, report the
limitation instead of retrying.";

/// Approval disabled: no way through.
const NO_APPROVAL_NOTICE: &str = "\
Approvals are disabled for this session, so writes outside these roots are
always denied. Do not retry them.";

/// What the generic veto message means.
const BLOCKED_NOTICE: &str = "\
A `write`/`edit` result saying \"blocked by `rpi-sandbox-extension`\" was handled
by the sandbox: when the user approved, the write was already applied — verify
with `read` instead of retrying.";

/// Cheap way to confirm isolation without probing the host.
const ENV_NOTICE: &str =
    "`RPI_SANDBOX_ACTIVE=1` in the environment confirms the sandbox; no other probe is needed.";

/// Render the block appended to the run's system prompt.
///
/// Protected paths are only counted: naming them would put secret locations
/// into the prompt, and `/sandbox` already shows the list to the user.
pub fn render(policy: &SandboxPolicy, isolated: bool, backend: Option<&str>) -> String {
    if !isolated {
        return format!(
            "{MARKER}\n\nThe rpi-sandbox extension is loaded, but this process is **not** \
             isolated: no kernel boundary is active, so only `write`/`edit` are gated and \
             `bash` is unconstrained. Start rpi through `rpis` for real isolation."
        );
    }

    let mut out = String::from(MARKER);
    out.push_str("\n\nThis process runs inside a kernel-enforced filesystem sandbox");
    if let Some(backend) = backend.map(str::trim).filter(|value| !value.is_empty()) {
        out.push_str(&format!(" ({backend})"));
    }
    out.push_str(".\n\nWritable roots:\n");

    if policy.writable.is_empty() {
        out.push_str("- (none)\n");
    } else {
        for rule in policy.writable.iter().take(MAX_ROOTS) {
            out.push_str(&format!("- {}\n", rule.path().display()));
        }
        if policy.writable.len() > MAX_ROOTS {
            out.push_str(&format!(
                "- (+{} more, listed by /sandbox)\n",
                policy.writable.len() - MAX_ROOTS
            ));
        }
    }

    out.push('\n');
    out.push_str(DENIAL_NOTICE);
    out.push_str("\n\n");
    if policy.approval.is_enabled() {
        out.push_str(APPROVAL_NOTICE);
        out.push_str("\n\n");
        out.push_str(BLOCKED_NOTICE);
    } else {
        out.push_str(NO_APPROVAL_NOTICE);
    }

    if !policy.protected.is_empty() {
        let count = policy.protected.len();
        out.push_str(&format!(
            "\n\n{count} protected {} by policy. Approvals cannot override {}, and\n\
             `bash` is not an exception.",
            if count == 1 { "path is" } else { "paths are" },
            if count == 1 { "it" } else { "them" },
        ));
    }

    out.push_str("\n\n");
    out.push_str(ENV_NOTICE);
    out
}

/// Append `block` to the run's prompt unless it is absent or already present.
///
/// `None` means "leave the prompt untouched". An empty prompt is never
/// rewritten: the transform replaces the whole system prompt, so returning only
/// the sandbox block there would delete everything else the host composed.
pub fn append_once(existing: &str, block: &str) -> Option<String> {
    if existing.trim().is_empty() || existing.contains(MARKER) {
        return None;
    }
    Some(format!("{}\n\n{}", existing.trim_end(), block))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rpi_sandbox_core::{ApprovalSettings, PathRule, SandboxMode};

    fn policy(writable: &[&str], protected: &[&str]) -> SandboxPolicy {
        SandboxPolicy {
            enabled: true,
            mode: SandboxMode::Auto,
            writable: writable
                .iter()
                .map(|path| PathRule::Dir(path.into()))
                .collect(),
            protected: protected
                .iter()
                .map(|path| PathRule::Dir(path.into()))
                .collect(),
            allow_file_writes: Vec::new(),
            approval: ApprovalSettings::default(),
            audit_log: None,
        }
    }

    #[test]
    fn isolated_block_names_roots_and_denial() {
        let text = render(&policy(&["/work/project"], &[]), true, Some("landlock"));
        assert!(text.starts_with(MARKER));
        assert!(text.contains("landlock"));
        assert!(text.contains("- /work/project"));
        assert!(text.contains("EACCES"));
        assert!(text.contains("权限不够"));
        assert!(text.contains("do not investigate"));
        assert!(text.contains("cannot request"));
        assert!(text.contains("approval, so a denied shell write stays denied"));
        assert!(text.contains("RPI_SANDBOX_ACTIVE=1"));
        assert!(!text.contains("protected by policy"));
    }

    #[test]
    fn protected_paths_are_counted_but_not_named() {
        let text = render(
            &policy(&["/work"], &["/home/user/.ssh", "/work/.env"]),
            true,
            None,
        );
        assert!(text.contains("2 protected paths are"));
        assert!(!text.contains("/home/user/.ssh"));
        assert!(!text.contains("/work/.env"));
    }

    #[test]
    fn roots_are_truncated() {
        let roots: Vec<String> = (0..14).map(|index| format!("/work/{index}")).collect();
        let refs: Vec<&str> = roots.iter().map(String::as_str).collect();
        let text = render(&policy(&refs, &[]), true, None);
        assert!(text.contains("- /work/0"));
        assert!(text.contains("- /work/11"));
        assert!(!text.contains("- /work/12"));
        assert!(text.contains("(+2 more"));
    }

    #[test]
    fn empty_writable_list_is_explicit() {
        let text = render(&policy(&[], &[]), true, None);
        assert!(text.contains("Writable roots:\n- (none)"));
    }

    #[test]
    fn disabled_approvals_change_the_guidance() {
        let mut policy = policy(&["/work"], &[]);
        policy.approval = ApprovalSettings {
            enabled: Some(false),
            ..ApprovalSettings::default()
        };
        let text = render(&policy, true, None);
        assert!(text.contains("Approvals are disabled"));
        assert!(!text.contains("can ask\nthe user"));
    }

    #[test]
    fn not_isolated_block_is_honest() {
        let text = render(&policy(&["/work"], &[]), false, None);
        assert!(text.contains("**not** isolated"));
        assert!(text.contains("`bash` is unconstrained"));
        assert!(text.contains("rpis"));
        assert!(!text.contains("Writable roots"));
    }

    #[test]
    fn append_keeps_the_existing_prompt() {
        let block = render(&policy(&["/work"], &[]), true, None);
        let merged = append_once("You are rpi.\n\nBe careful.", &block).unwrap();
        assert!(merged.starts_with("You are rpi.\n\nBe careful.\n\n## Sandbox"));
        assert!(merged.contains("- /work"));
    }

    #[test]
    fn append_is_idempotent() {
        let block = render(&policy(&["/work"], &[]), true, None);
        let merged = append_once("You are rpi.", &block).unwrap();
        assert!(append_once(&merged, &block).is_none());
    }

    #[test]
    fn empty_prompt_is_never_replaced() {
        assert!(append_once("", "block").is_none());
        assert!(append_once("   \n", "block").is_none());
    }
}
