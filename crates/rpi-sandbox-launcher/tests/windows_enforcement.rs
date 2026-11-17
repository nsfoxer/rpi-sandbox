//! End-to-end checks for the Windows MXC launcher.
//!
//! Every test spawns the real launcher and the `rpi-sandbox-probe` payload, so
//! the assertions cover the MXC filesystem policy, descendant inheritance, the
//! named-pipe broker, and exit-code propagation.
//!
//! Tests are skipped when the MXC backend reports no support.

#![cfg(target_os = "windows")]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn launcher() -> &'static str {
    env!("CARGO_BIN_EXE_rpis")
}

fn probe() -> &'static str {
    env!("CARGO_BIN_EXE_rpi-sandbox-probe")
}

/// One test workspace: a writable project dir, a dir outside every writable
/// root, and an isolated agent/state directory.
///
/// The root lives under `%LOCALAPPDATA%`, not `%TEMP%`: MXC exposes the system
/// temp directory as writable.
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

impl Drop for Layout {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn supported() -> bool {
    rpi_sandbox_core::probe().is_supported()
}

fn skip() -> bool {
    if supported() {
        false
    } else {
        eprintln!("MXC backend unavailable; skipping");
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
fn broker_serves_the_agent_but_rejects_children() {
    if skip() {
        return;
    }
    let layout = Layout::new();

    // The sandboxed agent itself is the broker's peer: hello must succeed.
    let hello = layout.run(&["broker-hello"]);
    assert!(
        hello.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&hello.stderr)
    );
    let text = stdout(&hello);
    assert!(text.contains("sandbox=windows-mxc"), "{text}");
    assert!(text.contains("profile=default"), "{text}");

    // The agent can approve and write an out-of-policy path through the broker.
    let outside = layout.deny().join("broker.txt");
    let write = layout.run(&[
        "broker-write",
        outside.to_str().unwrap(),
        "through the broker",
    ]);
    assert!(
        write.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&write.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(&outside).unwrap(),
        "through the broker"
    );

    // A child process has a different PID, so the broker must reject it. The
    // probe returns success only when the child's broker write fails.
    let rejected = layout.deny().join("child.txt");
    let child = layout.run(&["spawn-broker-write", rejected.to_str().unwrap(), "child"]);
    assert!(
        child.status.success(),
        "a child was allowed to use the broker; stderr: {}",
        String::from_utf8_lossy(&child.stderr)
    );
    assert!(!rejected.exists(), "a child wrote through the broker");
}

#[test]
fn readonly_subdirectories_stay_readable_but_not_writable() {
    if skip() {
        return;
    }
    let layout = Layout::new();
    let secret = layout.work().join("secret");
    std::fs::create_dir_all(&secret).unwrap();
    std::fs::write(secret.join("seed.txt"), "seed").unwrap();

    // Writing inside a readonly subdirectory is rejected by MXC's read-only
    // ranking, even though the parent is writable.
    let mut command = layout.base();
    command
        .arg("--no-extension")
        .arg("--rpi")
        .arg(probe())
        .arg("--readonly")
        .arg(secret.to_str().unwrap())
        .arg("--")
        .args(["write", secret.join("blocked.txt").to_str().unwrap(), "x"]);
    let output = command.output().expect("spawn the launcher");
    assert!(!output.status.success(), "readonly write must fail");
    assert!(!secret.join("blocked.txt").exists());

    // Reading it still works (unlike `denied_paths`).
    let mut command = layout.base();
    command
        .arg("--no-extension")
        .arg("--rpi")
        .arg(probe())
        .arg("--readonly")
        .arg(secret.to_str().unwrap())
        .arg("--")
        .args(["read", secret.join("seed.txt").to_str().unwrap()]);
    let output = command.output().expect("spawn the launcher");
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).contains("seed"));
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
    let extra = layout.root.join("extra");
    std::fs::create_dir_all(&extra).unwrap();
    let mut command = layout.base();
    command
        .arg("--no-extension")
        .arg("--rpi")
        .arg(probe())
        .arg("--write")
        .arg(extra.to_str().unwrap())
        .arg("--readonly")
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
fn print_plan_names_mxc_without_creating_any_container() {
    if skip() {
        return;
    }
    let layout = Layout::new();
    let mut command = layout.base();
    command.arg("--print-plan");
    let output = command.output().expect("spawn the launcher");
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("windows-mxc"), "{text}");
    assert!(text.contains("work"), "{text}");
    assert!(
        !layout.state().exists(),
        "--print-plan must not touch the filesystem"
    );
}

#[test]
fn runtime_bookkeeping_files_and_session_dir_are_writable() {
    if skip() {
        return;
    }
    let layout = Layout::new();
    let lease = layout.agent().join(".resource-lease");
    let session = layout.root.join("sessions");
    let session_file = session.join("note.txt");

    let output = layout.run(&[
        "write",
        lease.to_str().unwrap(),
        "lease",
        "--session-dir",
        session.to_str().unwrap(),
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(std::fs::read_to_string(&lease).unwrap(), "lease");

    let output = layout.run(&[
        "write",
        session_file.to_str().unwrap(),
        "session",
        "--session-dir",
        session.to_str().unwrap(),
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(std::fs::read_to_string(&session_file).unwrap(), "session");
}
