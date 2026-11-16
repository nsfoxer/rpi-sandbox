//! End-to-end checks for the Windows launcher.
//!
//! Every test spawns the real launcher and the `rpi-sandbox-probe` payload, so
//! the assertions cover the restricted token, the ACL edits, descendant
//! inheritance, the named-pipe broker, and ACL cleanup.
//!
//! Tests are skipped when the platform probe reports no backend (for example on
//! a Windows build without restricted-token support).

#![cfg(target_os = "windows")]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use rpi_sandbox_core::{ApprovalScope, BrokerClient, WriteOp};

fn launcher() -> &'static str {
    env!("CARGO_BIN_EXE_rpis")
}

fn probe() -> &'static str {
    env!("CARGO_BIN_EXE_rpi-sandbox-probe")
}

/// One test workspace: a writable project dir, a dir outside every writable
/// root, and an isolated agent/state directory.
///
/// The root deliberately lives under `%LOCALAPPDATA%`, not `%TEMP%`: the policy
/// makes the system temp directory writable, so a temp-based "outside" dir would
/// really be inside the allowlist.
struct Layout {
    root: PathBuf,
}

impl Layout {
    fn new() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let base = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let root = base.join("rpi-sandbox-tests").join(format!(
            "{}-{nonce}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(root.join("work")).unwrap();
        std::fs::create_dir_all(root.join("deny")).unwrap();
        std::fs::create_dir_all(root.join("agent")).unwrap();
        Self { root }
    }

    fn work(&self) -> PathBuf {
        self.root.join("work")
    }

    fn deny(&self) -> PathBuf {
        self.root.join("deny")
    }

    fn agent(&self) -> PathBuf {
        self.root.join("agent")
    }

    fn state(&self) -> PathBuf {
        self.root.join("state")
    }

    fn root(&self) -> &Path {
        &self.root
    }

    fn base(&self) -> Command {
        let mut command = Command::new(launcher());
        command
            .current_dir(self.work())
            .env("RPI_CODING_AGENT_DIR", self.agent())
            .env("RPI_SANDBOX_STATE_DIR", self.state());
        command
    }

    /// Run one probe command under the sandbox.
    fn run(&self, args: &[&str]) -> Output {
        let mut command = self.base();
        command.arg("--no-extension").arg("--rpi").arg(probe());
        command.arg("--").args(args);
        command.output().expect("spawn the launcher")
    }
}

fn supported() -> bool {
    rpi_sandbox_core::probe().is_supported()
}

fn skip() -> bool {
    if supported() {
        false
    } else {
        eprintln!("restricted-token backend unavailable; skipping");
        true
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).replace("\r\n", "\n")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).replace("\r\n", "\n")
}

#[test]
fn writable_roots_allow_writes_and_reads_stay_open() {
    if skip() {
        return;
    }
    let layout = Layout::new();
    let inside = layout.work().join("nested/ok.txt");
    std::fs::create_dir_all(inside.parent().unwrap()).unwrap();
    let output = layout.run(&["write", inside.to_str().unwrap(), "ok"]);
    assert!(
        output.status.success(),
        "in-root write failed: {}",
        stderr(&output)
    );
    assert_eq!(std::fs::read_to_string(&inside).unwrap(), "ok");

    // Reading outside the writable roots stays unrestricted.
    let outside = Path::new(r"C:\Windows\win.ini");
    if outside.is_file() {
        let output = layout.run(&["read", outside.to_str().unwrap()]);
        assert!(
            output.status.success(),
            "read must stay open: {}",
            stderr(&output)
        );
    }
}

#[test]
fn writes_outside_the_allowlist_are_denied() {
    if skip() {
        return;
    }
    let layout = Layout::new();
    let target = layout.deny().join("denied.txt");
    let output = layout.run(&["write", target.to_str().unwrap(), "no"]);
    assert!(!output.status.success(), "write outside must fail");
    assert!(!target.exists(), "the file must not be created");
    assert!(
        stderr(&output).contains("os error 5") || stderr(&output).to_lowercase().contains("denied"),
        "expected an access-denied error, got: {}",
        stderr(&output)
    );
}

#[test]
fn descendants_inherit_the_restriction() {
    if skip() {
        return;
    }
    let layout = Layout::new();
    let inside = layout.work().join("child.txt");
    let output = layout.run(&["spawn-write", inside.to_str().unwrap(), "ok"]);
    assert!(
        output.status.success(),
        "grandchild write inside failed: {}",
        stderr(&output)
    );
    assert_eq!(std::fs::read_to_string(&inside).unwrap(), "ok");

    let outside = layout.deny().join("child.txt");
    let output = layout.run(&["spawn-write", outside.to_str().unwrap(), "no"]);
    assert!(
        !output.status.success(),
        "grandchild write outside must fail"
    );
    assert!(!outside.exists());
}

#[test]
fn the_sandbox_cannot_rewrite_its_own_dacl() {
    if skip() {
        return;
    }
    let layout = Layout::new();
    let target = layout.work().join("acl.txt");
    std::fs::write(&target, "x").unwrap();
    let output = layout.run(&["set-acl", target.to_str().unwrap()]);
    assert!(output.status.success(), "probe failed: {}", stderr(&output));
    assert!(
        stdout(&output).contains("set-acl denied"),
        "the DACL rewrite must be denied: {}",
        stdout(&output)
    );
}

#[test]
fn broker_serves_approvals_over_the_named_pipe() {
    if skip() {
        return;
    }
    let layout = Layout::new();
    let mut child = layout
        .base()
        .arg("--no-extension")
        .arg("--rpi")
        .arg(probe())
        .arg("--")
        .args(["hold", "4000"])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn the launcher");

    let stdout = child.stdout.take().expect("stdout is piped");
    let mut reader = BufReader::new(stdout);
    let mut endpoint = String::new();
    reader
        .read_line(&mut endpoint)
        .expect("read the broker endpoint");
    let endpoint = endpoint.trim();
    assert!(
        endpoint.starts_with(r"\\.\pipe\rpi-sandbox-"),
        "unexpected endpoint: {endpoint}"
    );

    let client = BrokerClient::connect(Path::new(endpoint)).expect("connect to the broker");
    let hello = client.hello("rpi-sandbox-test", "0.1.0").unwrap();
    assert_eq!(hello.sandbox.as_deref(), Some("windows-restricted-token"));
    assert_eq!(hello.profile.as_deref(), Some("default"));

    let outside = layout.deny().join("broker.txt");
    assert!(!client.is_approved(&outside, WriteOp::Create));
    client
        .approve(
            &outside,
            &[WriteOp::Create, WriteOp::Overwrite],
            ApprovalScope::Session,
            false,
        )
        .unwrap();
    client.write(&outside, b"through the broker").unwrap();
    assert_eq!(
        std::fs::read_to_string(&outside).unwrap(),
        "through the broker"
    );
    client.revoke(&outside, false).unwrap();
    assert!(!client.is_approved(&outside, WriteOp::Create));
    drop(client);

    let status = child.wait().unwrap();
    assert!(status.success(), "launcher exited with {status}");
}

#[test]
fn acl_edits_are_revoked_on_exit() {
    if skip() {
        return;
    }
    let layout = Layout::new();
    let (read_sid, write_sid) = capability_sids(&layout);
    let output = layout.run(&["write", layout.work().join("a.txt").to_str().unwrap(), "x"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        !acl_contains(&layout.work(), &write_sid),
        "the write capability SID must be removed on exit"
    );
    // Read roots get an ACE too (the target's ACL may only grant the user).
    assert!(
        !acl_contains(&layout.agent(), &read_sid),
        "the read capability SID must be removed on exit"
    );
    // The journal must be gone as well.
    let journals = std::fs::read_dir(layout.state().join("acl"))
        .map(|entries| entries.count())
        .unwrap_or(0);
    assert_eq!(journals, 0, "no journal may survive a clean run");
}

#[test]
fn orphaned_acl_edits_are_recovered_on_the_next_run() {
    if skip() {
        return;
    }
    let layout = Layout::new();
    let (_, sid) = capability_sids(&layout);
    let mut child = layout
        .base()
        .arg("--no-extension")
        .arg("--rpi")
        .arg(probe())
        .arg("--")
        .args(["hold", "8000"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the launcher");

    // Wait until the ACE is applied.
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && !acl_contains(&layout.work(), &sid) {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        acl_contains(&layout.work(), &sid),
        "the ACE was never applied"
    );

    // Simulate a killed launcher: the journal stays behind.
    child.kill().unwrap();
    let _ = child.wait();
    let journals = std::fs::read_dir(layout.state().join("acl"))
        .map(|entries| entries.count())
        .unwrap_or(0);
    assert_eq!(journals, 1, "the orphaned run must leave a journal");

    // The next run sweeps the journal before applying its own plan.
    let output = layout.run(&[
        "write",
        layout.work().join("after.txt").to_str().unwrap(),
        "x",
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        !acl_contains(&layout.work(), &sid),
        "orphaned ACE must be revoked by the next run"
    );
}

#[test]
fn explicit_bypass_does_not_claim_isolation() {
    if skip() {
        return;
    }
    let layout = Layout::new();
    let mut command = layout.base();
    command
        .arg("--no-sandbox")
        .arg("--no-extension")
        .arg("--rpi")
        .arg(probe())
        .arg("--")
        .args(["env", "RPI_SANDBOX_ACTIVE"]);
    let output = command.output().expect("spawn the launcher");
    assert!(
        !output.status.success(),
        "RPI_SANDBOX_ACTIVE must not be set without isolation"
    );
}

#[test]
fn cli_paths_are_exported_to_the_extension() {
    if skip() {
        return;
    }
    let layout = Layout::new();
    let extra = layout.root().join("extra");
    std::fs::create_dir_all(&extra).unwrap();
    let mut command = layout.base();
    command
        .arg("--no-extension")
        .arg("--rpi")
        .arg(probe())
        .arg("--write")
        .arg(extra.to_str().unwrap())
        .arg("--protect")
        .arg(layout.deny().to_str().unwrap())
        .arg("--")
        .args(["env", "RPI_SANDBOX_WRITABLE"]);
    let output = command.output().expect("spawn the launcher");
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output).trim(), extra.to_str().unwrap());
}

#[test]
fn exit_codes_are_propagated() {
    if skip() {
        return;
    }
    let layout = Layout::new();
    let output = layout.run(&["exit", "7"]);
    assert_eq!(output.status.code(), Some(7));
}

#[test]
fn print_plan_describes_the_backend_without_touching_acls() {
    if skip() {
        return;
    }
    let layout = Layout::new();
    let (_, sid) = capability_sids(&layout);
    let mut command = layout.base();
    command.arg("--print-plan");
    let output = command.output().expect("spawn the launcher");
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("windows-restricted-token"), "{text}");
    assert!(text.contains("work"), "{text}");
    assert!(
        !acl_contains(&layout.work(), &sid),
        "--print-plan must not modify the filesystem"
    );
}

impl Drop for Layout {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Capability SIDs for this layout, as printed by `--print-sid`.
fn capability_sids(layout: &Layout) -> (String, String) {
    let mut command = layout.base();
    command.arg("--print-sid");
    let output = command.output().expect("spawn --print-sid");
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    let read = sid_line(&text, "read");
    let write = sid_line(&text, "write");
    (read, write)
}

fn sid_line(text: &str, kind: &str) -> String {
    text.lines()
        .find_map(|line| line.trim().strip_prefix(kind).map(str::trim))
        .and_then(|line| line.strip_prefix('='))
        .map(|line| line.trim().to_string())
        .unwrap_or_else(|| {
            panic!(
                "{kind} SID line missing from:
{text}"
            )
        })
}

/// Whether `icacls` reports the SID on `path`.
fn acl_contains(path: &Path, sid: &str) -> bool {
    let output = Command::new("icacls")
        .arg(path)
        .output()
        .expect("run icacls");
    let text = String::from_utf8_lossy(&output.stdout);
    text.contains(sid)
}
