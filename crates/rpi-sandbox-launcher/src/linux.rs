//! Linux backend: Landlock domain + forked broker + `exec`.
//!
//! Landlock is per-thread and inherited across `exec`, so the launcher applies
//! it to itself *after* forking the broker and immediately before replacing
//! itself with `rpi`. The forked parent stays unconfined and serves approvals,
//! then reaps the agent and exits with its status.

use std::io::BufReader;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

use rpi_sandbox_core::backend::{BackendCapabilities, BackendPlan, LaunchSpec, SandboxBackend};
use rpi_sandbox_core::protocol::env;
use rpi_sandbox_core::{
    linux, BrokerConfig, BrokerService, Listener, SandboxMode, SandboxPolicy, SandboxSupport,
};

/// The single Linux backend instance.
pub static BACKEND: LandlockBackend = LandlockBackend;

/// Landlock-backed launcher.
pub struct LandlockBackend;

impl SandboxBackend for LandlockBackend {
    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            name: "landlock",
            can_subtract_readonly: false,
            persistent_side_effects: false,
            needs_read_roots: false,
            missing_root_is_fatal: false,
        }
    }

    fn support(&self) -> SandboxSupport {
        rpi_sandbox_core::probe()
    }

    fn plan(&self, policy: &SandboxPolicy) -> Result<BackendPlan, String> {
        linux::plan(policy).map(BackendPlan::Landlock)
    }

    fn launch(&self, plan: &BackendPlan, spec: LaunchSpec) -> Result<i32, String> {
        let BackendPlan::Landlock(plan) = plan else {
            return Err("the Linux backend received a non-Landlock plan".to_string());
        };

        // The broker is forked before the domain is applied so it stays
        // unconfined; the agent side keeps only the endpoint name.
        let socket = match spec.broker.clone() {
            Some(config) => {
                let listener = Listener::bind()
                    .map_err(|error| format!("cannot start the approval broker: {error}"))?;
                // SAFETY: the launcher is still single-threaded here, so the
                // child only inherits the state created above.
                let pid = unsafe { libc::fork() };
                if pid < 0 {
                    return Err(format!(
                        "cannot fork the approval broker: {}",
                        std::io::Error::last_os_error()
                    ));
                }
                if pid == 0 {
                    // Agent side: drop our copy of the listener but keep the
                    // name; the broker parent still owns the bound socket.
                    Some(listener.into_name())
                } else {
                    supervise(listener, pid, config);
                }
            }
            None => None,
        };

        match linux::apply(plan) {
            Ok(()) => exec_confined(&spec, socket.as_deref()),
            Err(error) => {
                if spec.policy.mode == SandboxMode::Required {
                    Err(format!("cannot apply the filesystem sandbox: {error}"))
                } else {
                    eprintln!("warning: {error}; running without a sandbox");
                    let mut spec = spec;
                    spec.env.remove_isolation_claims();
                    exec_confined(&spec, None)
                }
            }
        }
    }
}

/// Replace the process with the target command.
fn exec_confined(spec: &LaunchSpec, socket: Option<&Path>) -> Result<i32, String> {
    let mut command = Command::new(&spec.program);
    command.args(&spec.args);
    spec.env.apply(&mut command);
    if let Some(socket) = socket {
        command.env(env::SOCKET, socket);
    }
    let error = command.exec();
    Err(format!("cannot exec {}: {error}", spec.program.display()))
}

/// Parent process: serve approvals on a thread and reap the agent.
///
/// Waiting in the main thread keeps the exit code authoritative even when the
/// broker thread is still blocked on a connection that never arrives.
fn supervise(listener: Listener, child: libc::pid_t, config: BrokerConfig) -> ! {
    // The child owns terminal input; the broker must outlive Ctrl+C so a
    // still-running agent keeps its approval channel.
    // SAFETY: signal dispositions are process-wide and the broker renders no UI.
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_IGN);
        libc::signal(libc::SIGTERM, libc::SIG_IGN);
    }

    std::thread::spawn(move || match listener.accept() {
        Ok(conn) => {
            let read_half = match conn.try_clone() {
                Ok(half) => half,
                Err(error) => {
                    eprintln!("warning: sandbox broker cannot read its socket: {error}");
                    return;
                }
            };
            // One service per session keeps approvals across reconnects.
            let mut service = BrokerService::new(config);
            if let Err(error) = service.serve_connection(BufReader::new(read_half), conn) {
                eprintln!("warning: sandbox broker stopped: {error}");
            }
        }
        Err(error) => eprintln!("warning: sandbox broker accept failed: {error}"),
    });

    let code = wait_child(child);
    std::process::exit(code);
}

fn wait_child(child: libc::pid_t) -> i32 {
    let mut status = 0;
    loop {
        // SAFETY: `status` is a valid out pointer.
        let result = unsafe { libc::waitpid(child, &mut status, 0) };
        if result == child {
            return exit_code(status);
        }
        if result < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return 1;
    }
}

fn exit_code(status: i32) -> i32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        1
    }
}
