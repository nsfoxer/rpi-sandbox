//! Windows backend: Microsoft Execution Containers (MXC).
//!
//! MXC's `processcontainer` is an OS-native process sandbox that takes a
//! filesystem policy instead of mutating ACLs. It therefore has no per-run
//! filesystem side effects and no cost proportional to the size of the project.
//!
//! The launcher stays unconfined and serves the approval broker over a named
//! pipe; the agent runs inside the container.

use std::path::{Path, PathBuf};

use mxc_sdk::v1::{self, SpawnExtendedOptions, SpawnStdio, WaitResult};
use rpi_sandbox_core::backend::{BackendCapabilities, BackendPlan, LaunchSpec, SandboxBackend};
use rpi_sandbox_core::mxc_plan::MxcPlan;
use rpi_sandbox_core::protocol::env;
use rpi_sandbox_core::{BrokerConfig, BrokerService, Listener, SandboxPolicy, SandboxSupport};

/// The single Windows backend instance.
pub static BACKEND: MxcBackend = MxcBackend;

/// MXC-backed launcher.
pub struct MxcBackend;

impl SandboxBackend for MxcBackend {
    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            name: "windows-mxc",
            // `denied_paths` can subtract a protected subtree.
            can_subtract_protected: true,
            // MXC applies the policy per container; no ACLs to roll back.
            persistent_side_effects: false,
            // MXC only exposes explicitly listed roots (plus system defaults).
            needs_read_roots: true,
            // A missing writable root is simply not created.
            missing_root_is_fatal: false,
        }
    }

    fn support(&self) -> SandboxSupport {
        rpi_sandbox_core::probe()
    }

    fn plan(&self, policy: &SandboxPolicy) -> Result<BackendPlan, String> {
        Ok(BackendPlan::Mxc(MxcPlan::build(policy, &[])))
    }

    fn launch(&self, plan: &BackendPlan, spec: LaunchSpec) -> Result<i32, String> {
        let BackendPlan::Mxc(_) = plan else {
            return Err("the Windows backend received a non-MXC plan".to_string());
        };
        // `plan()` has no read roots; rebuild with the launcher's set.
        let plan = MxcPlan::build(&spec.policy, &spec.read_roots);
        // 1. Broker endpoint before the child starts, so the extension can
        //    connect during library initialization.
        let mut child_env = spec.env.clone();
        if let Some(config) = spec.broker.clone() {
            // `ALL APPLICATION PACKAGES` (S-1-15-2-1): the MXC workload runs
            // in an AppContainer, and an AppContainer cannot open a pipe whose
            // DACL only grants the interactive user.
            let listener = Listener::bind_with_sids(&["S-1-15-2-1".to_string()])
                .map_err(|error| format!("cannot create the broker pipe: {error}"))?;
            child_env.set(env::SOCKET, listener.name().as_os_str());
            start_broker(listener, config);
        }

        // 2. Environment: MXC inherits the host environment, but MSYS2's
        //    POSIX PATH/TEMP would break native Windows children.
        let environment = mxc_environment(&child_env, &spec);

        // 3. Container request.
        let command = command_line(&spec.program, &spec.args);
        let request = v1::ContainerRequest {
            filesystem: Some(v1::FilesystemPolicy {
                readwrite_paths: display_paths(&plan.readwrite),
                readonly_paths: display_paths(&plan.readonly),
                denied_paths: display_paths(&plan.denied),
                clear_policy_on_exit: None,
            }),
            // MXC denies egress by default; rpi needs the model API.
            network: Some(v1::NetworkPolicy {
                egress: Some(v1::NetworkEgressPolicy {
                    default: Some(v1::NetworkAction::Allow),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            // `disable = true` removes Win32k. rpi statically imports
            // ole32/USER32/SHELL32, and ole32's DllMain fails (1114) without
            // Win32k, so the container must keep windows enabled.
            ui: Some(v1::UiPolicy {
                disable: false,
                clipboard: v1::ClipboardPolicy::None,
                allow_input_injection: false,
            }),
            containment: v1::Containment::Process,
            working_directory: Some(spec.cwd.display().to_string()),
            environment: Some(environment),
            inherit_default_environment: Some(true),
            timeout_ms: None,
            ..v1::ContainerRequest::new(command)
        };

        // 4. Spawn with the caller's own stdio: the TUI needs the terminal.
        let mut options = SpawnExtendedOptions::default();
        options.stdio = SpawnStdio::Inherit;
        let mut process = v1::spawn_with_extended_options(request, options)
            .map_err(|error| format!("cannot start the MXC container: {error}"))?;

        match process
            .wait()
            .map_err(|error| format!("cannot wait for the MXC container: {error}"))?
        {
            WaitResult::Exited(code) => Ok(code),
            WaitResult::TimedOut => Err("the MXC container timed out".to_string()),
        }
    }
}

/// Start the approval broker on its own thread.
fn start_broker(listener: Listener, config: BrokerConfig) {
    std::thread::spawn(move || match listener.accept() {
        Ok(conn) => {
            let read_half = match conn.try_clone() {
                Ok(half) => half,
                Err(error) => {
                    eprintln!("warning: sandbox broker cannot read its pipe: {error}");
                    return;
                }
            };
            let mut service = BrokerService::new(config);
            if let Err(error) = service.serve_connection(std::io::BufReader::new(read_half), conn) {
                eprintln!("warning: sandbox broker stopped: {error}");
            }
        }
        Err(error) => eprintln!("warning: sandbox broker accept failed: {error}"),
    });
}

/// Fold the launcher environment into MXC's `environment` list.
///
/// Values with native Windows paths are forced: the launcher may run under
/// MSYS2, whose `PATH=/usr/local/bin:...` and `TEMP=/tmp` are meaningless to a
/// native Windows child.
fn mxc_environment(
    env: &rpi_sandbox_core::backend::SandboxEnv,
    spec: &LaunchSpec,
) -> Vec<(String, String)> {
    let mut entries: Vec<(String, String)> = env
        .overlay(std::env::vars_os())
        .into_iter()
        .filter_map(|(name, value)| {
            Some((
                name.to_string_lossy().into_owned(),
                value.to_string_lossy().into_owned(),
            ))
        })
        .collect();

    set_entry(&mut entries, "PATH", windows_path(spec.program.parent()));
    let temp = windows_temp();
    set_entry(&mut entries, "TEMP", temp.display().to_string());
    set_entry(&mut entries, "TMP", temp.display().to_string());
    entries
}

fn set_entry(entries: &mut Vec<(String, String)>, name: &str, value: impl Into<String>) {
    let value = value.into();
    entries.retain(|(existing, _)| !existing.eq_ignore_ascii_case(name));
    entries.push((name.to_string(), value));
}

/// A native Windows `PATH`.
fn windows_path(program_dir: Option<&Path>) -> String {
    let mut parts: Vec<PathBuf> = Vec::new();
    let mut push = |path: PathBuf| {
        if path.is_dir() && !parts.contains(&path) {
            parts.push(path);
        }
    };
    if let Some(dir) = program_dir {
        push(dir.to_path_buf());
    }
    for candidate in [
        r"C:\Windows\System32",
        r"C:\Windows",
        r"C:\msys64\usr\bin",
        r"C:\msys64\mingw64\bin",
        r"C:\Program Files\Git\cmd",
    ] {
        push(PathBuf::from(candidate));
    }
    // Keep any native entries that were already present.
    if let Some(existing) = std::env::var_os("PATH") {
        let text = existing.to_string_lossy();
        if !text.starts_with('/') {
            for part in text.split(';') {
                if !part.is_empty() {
                    push(PathBuf::from(part));
                }
            }
        }
    }
    if parts.is_empty() {
        return r"C:\Windows\System32;C:\Windows".to_string();
    }
    parts
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(";")
}

/// A native Windows temp directory.
fn windows_temp() -> PathBuf {
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        return PathBuf::from(local).join("Temp");
    }
    std::env::temp_dir()
}

fn display_paths(paths: &[PathBuf]) -> Vec<String> {
    paths
        .iter()
        .map(|path| path.display().to_string())
        .collect()
}

/// Build a Windows command line from the resolved program and arguments.
fn command_line(program: &Path, args: &[String]) -> String {
    let mut parts = vec![quote(&program.display().to_string())];
    parts.extend(args.iter().map(|arg| quote(arg)));
    parts.join(" ")
}

/// Quote one argument using the Windows `CommandLineToArgvW` rules.
fn quote(value: &str) -> String {
    if value.is_empty() {
        return "\"\"".to_string();
    }
    if !value.contains([' ', '\t', '"']) {
        return value.to_string();
    }
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    let mut backslashes = 0usize;
    for character in value.chars() {
        match character {
            '\\' => backslashes += 1,
            '"' => {
                out.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            other => {
                out.extend(std::iter::repeat_n('\\', backslashes));
                out.push(other);
                backslashes = 0;
            }
        }
    }
    out.extend(std::iter::repeat_n('\\', backslashes * 2));
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_arguments_are_not_quoted() {
        assert_eq!(quote("--version"), "--version");
        assert_eq!(quote(r"C:\work\rpi.exe"), r"C:\work\rpi.exe");
    }

    #[test]
    fn spaces_and_quotes_are_escaped() {
        assert_eq!(quote("a b"), "\"a b\"");
        assert_eq!(quote(r#"a"b"#), "\"a\\\"b\"");
        assert_eq!(quote(""), "\"\"");
    }

    #[test]
    fn command_line_quotes_the_program() {
        let line = command_line(Path::new(r"C:\Program Files\rpi.exe"), &["-p".into()]);
        assert_eq!(line, r#""C:\Program Files\rpi.exe" -p"#);
    }
}
