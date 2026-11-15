//! End-to-end checks for the Linux launcher.
//!
//! Each test spawns the real launcher and a small `/bin/sh` payload, so the
//! assertions exercise fork, Landlock, `exec`, and process inheritance. Tests
//! skip themselves when the kernel has no Landlock support.

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rpi_sandbox_core::{ApprovalScope, BrokerClient, WriteOp};

fn launcher() -> &'static str {
    env!("CARGO_BIN_EXE_rpi-sandbox")
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

fn shell(script: &str) -> Vec<String> {
    vec!["/bin/sh".to_string(), "-c".to_string(), script.to_string()]
}

fn run_shell(prefix: &[&str], script: &str) -> Output {
    let mut args: Vec<String> = prefix.iter().map(|value| value.to_string()).collect();
    args.push("--".to_string());
    args.extend(shell(script));
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
fn broker_approves_and_revokes_out_of_policy_writes() {
    if !landlock_available() {
        eprintln!("landlock unavailable; skipping");
        return;
    }
    let allowed = tempfile::tempdir().unwrap();
    let Some(denied) = DeniedDir::new() else {
        eprintln!("/var/tmp unavailable; skipping");
        return;
    };
    let socket_file = allowed.path().join("socket");
    let profile_file = allowed.path().join("profile");
    let outside = denied.path().join("broker.txt");
    let script = format!(
        "printf '%s' \"$RPI_SANDBOX_SOCKET\" > '{}'; printf '%s' \"$RPI_SANDBOX_PROFILE\" > '{}'; sleep 2",
        socket_file.display(),
        profile_file.display()
    );
    let mut command = Command::new(launcher());
    command.arg("--");
    command.args(shell(&script));
    let mut child = command.spawn().expect("spawn launcher");

    let socket_path = wait_for_value(&socket_file, Duration::from_secs(5))
        .expect("broker socket path was not published");
    assert!(socket_path.ends_with(".sock"), "{socket_path}");
    assert_eq!(std::fs::read_to_string(&profile_file).unwrap(), "default");

    let client = BrokerClient::connect(Path::new(&socket_path)).expect("connect to broker");
    let hello = client.hello("rpi-sandbox-test", "0.1.0").unwrap();
    assert_eq!(hello.sandbox.as_deref(), Some("landlock"));
    assert_eq!(hello.profile.as_deref(), Some("default"));

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
    let protected_file = allowed.path().join("protected");
    let script = format!(
        "printf '%s' \"$RPI_SANDBOX_WRITABLE\" > '{}'; printf '%s' \"$RPI_SANDBOX_PROTECTED\" > '{}'",
        writable_file.display(),
        protected_file.display()
    );
    let output = run_shell(
        &["--write", "/srv/data", "--protect", "/srv/secrets"],
        &script,
    );
    assert!(output.status.success());
    assert_eq!(std::fs::read_to_string(writable_file).unwrap(), "/srv/data");
    assert_eq!(
        std::fs::read_to_string(protected_file).unwrap(),
        "/srv/secrets"
    );
}

#[test]
fn exit_codes_are_propagated() {
    let output = run_shell(&[], "exit 7");
    assert_eq!(output.status.code(), Some(7));
}

fn wait_for_value(path: &Path, timeout: Duration) -> Option<String> {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if let Ok(value) = std::fs::read_to_string(path) {
            if !value.is_empty() {
                return Some(value);
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}
