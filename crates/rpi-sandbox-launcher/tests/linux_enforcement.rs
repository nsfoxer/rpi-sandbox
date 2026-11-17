//! End-to-end checks for the Linux launcher.
//!
//! Each test spawns the real launcher and a small `/bin/sh` payload, so the
//! assertions exercise fork, Landlock, `exec`, and process inheritance. Tests
//! skip themselves when the kernel has no Landlock support.

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

fn launcher() -> &'static str {
    env!("CARGO_BIN_EXE_rpis")
}

fn probe() -> &'static str {
    env!("CARGO_BIN_EXE_rpi-sandbox-probe")
}

fn landlock_available() -> bool {
    rpi_sandbox_core::probe().is_supported()
}

fn run(args: &[&str]) -> Output {
    Command::new(launcher())
        .args(args)
        .output()
        .expect("spawn the launcher")
}

/// A writable location outside the workspace, the system temp dir, and the
/// launcher's automatic roots.
struct DeniedDir(PathBuf);

impl DeniedDir {
    fn new() -> Option<Self> {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let base = Path::new("/var/tmp");
        if !base.is_dir() {
            return None;
        }
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let dir = base.join(format!(
            "rpi-sandbox-test-{}-{nonce}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir).ok()?;
        Some(Self(dir))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for DeniedDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run_shell(prefix: &[&str], script: &str) -> Output {
    let mut args: Vec<String> = prefix.iter().map(|value| value.to_string()).collect();
    // Tests drive `/bin/sh` as the "rpi" binary and disable automatic extension
    // loading so the bundled cdylib does not become a shell argument.
    args.extend([
        "--no-extension".to_string(),
        "--rpi".to_string(),
        "/bin/sh".to_string(),
        "-c".to_string(),
        script.to_string(),
    ]);
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    run(&borrowed)
}

#[test]
fn allowed_paths_are_writable_and_reads_stay_open() {
    if !landlock_available() {
        eprintln!("landlock unavailable; skipping");
        return;
    }
    let allowed = tempfile::tempdir().unwrap();
    let target = allowed.path().join("nested/ok.txt");
    let script = format!(
        "mkdir -p '{}' && echo ok > '{}' && cat /etc/hosts",
        allowed.path().join("nested").display(),
        target.display()
    );
    let output = run_shell(&[], &script);
    assert!(
        output.status.success(),
        "launcher failed: {:?}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read_to_string(&target).unwrap().trim(), "ok");
}

#[test]
fn writes_outside_the_allowlist_are_denied() {
    if !landlock_available() {
        eprintln!("landlock unavailable; skipping");
        return;
    }
    let Some(denied) = DeniedDir::new() else {
        eprintln!("/var/tmp unavailable; skipping");
        return;
    };
    let target = denied.path().join("denied.txt");
    let script = format!("echo no > '{}'", target.display());
    let output = run_shell(&[], &script);
    assert!(!output.status.success(), "write outside must fail");
    assert!(!target.exists());
}

#[test]
fn descendants_inherit_the_domain() {
    if !landlock_available() {
        eprintln!("landlock unavailable; skipping");
        return;
    }
    let allowed = tempfile::tempdir().unwrap();
    let Some(denied) = DeniedDir::new() else {
        eprintln!("/var/tmp unavailable; skipping");
        return;
    };
    let allowed_target = allowed.path().join("child.txt");
    let denied_target = denied.path().join("child.txt");
    let inside = format!("sh -c 'echo ok > {}'", allowed_target.display());
    let outside = format!("sh -c 'echo no > {}'", denied_target.display());
    let script = format!("{inside} && {outside}");
    let output = run_shell(&[], &script);
    assert!(
        !output.status.success(),
        "grandchild write outside must fail"
    );
    assert_eq!(
        std::fs::read_to_string(&allowed_target).unwrap().trim(),
        "ok"
    );
    assert!(!denied_target.exists());
}

#[test]
fn broker_approves_the_agent_but_rejects_children() {
    if !landlock_available() {
        eprintln!("landlock unavailable; skipping");
        return;
    }
    let Some(denied) = DeniedDir::new() else {
        eprintln!("/var/tmp unavailable; skipping");
        return;
    };
    let outside = denied.path().join("broker.txt");
    let probe = env!("CARGO_BIN_EXE_rpi-sandbox-probe");

    // The sandboxed agent itself is the broker's peer: hello must succeed.
    let hello = run(&["--no-extension", "--rpi", probe, "--", "broker-hello"]);
    assert!(
        hello.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&hello.stderr)
    );
    let stdout = String::from_utf8_lossy(&hello.stdout);
    assert!(stdout.contains("sandbox=landlock"), "{stdout}");
    assert!(stdout.contains("profile=default"), "{stdout}");

    // The agent can approve and write an out-of-policy path through the broker.
    let write = run(&[
        "--no-extension",
        "--rpi",
        probe,
        "--",
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
    let rejected = denied.path().join("child.txt");
    let child = run(&[
        "--no-extension",
        "--rpi",
        probe,
        "--",
        "spawn-broker-write",
        rejected.to_str().unwrap(),
        "child",
    ]);
    assert!(
        child.status.success(),
        "a child was allowed to use the broker; stderr: {}",
        String::from_utf8_lossy(&child.stderr)
    );
    assert!(!rejected.exists(), "a child wrote through the broker");
}

#[test]
fn no_broker_still_confines_but_leaves_out_of_policy_writes_unavailable() {
    if !landlock_available() {
        eprintln!("landlock unavailable; skipping");
        return;
    }
    let allowed = tempfile::tempdir().unwrap();
    let active_file = allowed.path().join("active");
    let socket_file = allowed.path().join("socket");
    let script = format!(
        "printf '%s' \"$RPI_SANDBOX_ACTIVE\" > '{}'; printf '%s' \"${{RPI_SANDBOX_SOCKET:-none}}\" > '{}'",
        active_file.display(),
        socket_file.display()
    );
    let output = run_shell(&["--no-broker"], &script);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read_to_string(&active_file).unwrap(), "1");
    assert_eq!(std::fs::read_to_string(&socket_file).unwrap(), "none");
}

#[test]
fn explicit_bypass_does_not_claim_isolation() {
    let allowed = tempfile::tempdir().unwrap();
    let active_file = allowed.path().join("active");
    let script = format!(
        "printf '%s' \"${{RPI_SANDBOX_ACTIVE:-none}}\" > '{}'",
        active_file.display()
    );
    let output = run_shell(&["--no-sandbox"], &script);
    assert!(output.status.success());
    assert_eq!(std::fs::read_to_string(&active_file).unwrap(), "none");
}

#[test]
fn cli_paths_are_exported_to_the_extension() {
    if !landlock_available() {
        eprintln!("landlock unavailable; skipping");
        return;
    }
    let allowed = tempfile::tempdir().unwrap();
    let writable_file = allowed.path().join("writable");
    let readonly_file = allowed.path().join("readonly");
    let script = format!(
        "printf '%s' \"$RPI_SANDBOX_WRITABLE\" > '{}'; printf '%s' \"$RPI_SANDBOX_READONLY\" > '{}'",
        writable_file.display(),
        readonly_file.display()
    );
    let output = run_shell(
        &["--write", "/srv/data", "--readonly", "/srv/secrets"],
        &script,
    );
    assert!(output.status.success());
    assert_eq!(std::fs::read_to_string(writable_file).unwrap(), "/srv/data");
    assert_eq!(
        std::fs::read_to_string(readonly_file).unwrap(),
        "/srv/secrets"
    );
}

#[test]
fn exit_codes_are_propagated() {
    let output = run_shell(&[], "exit 7");
    assert_eq!(output.status.code(), Some(7));
}

#[test]
fn runtime_bookkeeping_files_and_session_dir_are_writable() {
    if !landlock_available() {
        eprintln!("landlock unavailable; skipping");
        return;
    }
    let Some(base) = DeniedDir::new() else {
        eprintln!("/var/tmp unavailable; skipping");
        return;
    };
    let agent = base.path().join("agent");
    let session = base.path().join("sessions");
    let lease = agent.join(".resource-lease");
    let session_file = session.join("note.txt");

    let write = |target: &Path, content: &str| {
        Command::new(launcher())
            .env("RPI_CODING_AGENT_DIR", &agent)
            .arg("--no-extension")
            .arg("--rpi")
            .arg(probe())
            .arg("--")
            .arg("write")
            .arg(target)
            .arg(content)
            .arg("--session-dir")
            .arg(&session)
            .output()
            .expect("spawn the launcher")
    };

    let output = write(&lease, "lease");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read_to_string(&lease).unwrap(), "lease");

    let output = write(&session_file, "session");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read_to_string(&session_file).unwrap(), "session");
}
