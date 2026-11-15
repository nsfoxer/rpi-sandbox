//! Linux launcher: parse, fork the broker, apply Landlock, and `exec`.

use std::ffi::OsString;
use std::fs::Permissions;
use std::io::BufReader;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use rpi_sandbox_core::protocol::env;
use rpi_sandbox_core::{
    compile_policy, linux, load_settings_file, normalize_and_resolve, probe, BrokerConfig,
    PolicyContext, PolicyOverrides, SandboxMode, SandboxPolicy, SandboxSupport, PROTOCOL_VERSION,
};

const HELP: &str = "\
rpi-sandbox — run rpi inside a whole-process filesystem sandbox

Usage:
  rpi-sandbox [options] -- <rpi args...>

Options:
  --profile <name>     Profile label advertised on the broker socket
  --config <path>      Global settings file (default: ~/.rpi/agent/sandbox.json)
  --write <dir>        Extra writable directory (repeatable)
  --protect <path>     Extra protected path (repeatable)
  --mode <mode>        auto | required | off
  --audit <path>       Broker audit log
  --no-broker          Do not start the approval broker
  --no-sandbox         Run without isolation (explicit bypass)
  -h, --help           Show this help
  -V, --version        Show the version

The sandbox is opt-in: invoking this launcher is the explicit request. Set
RPI_SANDBOX=0 or pass --no-sandbox to bypass it for one run.";

/// Subcommands that legitimately write outside the workspace.
const MAINTENANCE: [&str; 12] = [
    "install",
    "uninstall",
    "auth",
    "update",
    "extension",
    "package",
    "resource",
    "events",
    "session",
    "dev",
    "dev-local",
    "__rpi_dev_cleanup",
];

/// Parsed command line.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Args {
    profile: String,
    config: Option<PathBuf>,
    writable: Vec<String>,
    protected: Vec<String>,
    mode: Option<SandboxMode>,
    audit: Option<PathBuf>,
    broker: bool,
    enabled: Option<bool>,
    target: Vec<String>,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            profile: "default".to_string(),
            config: None,
            writable: Vec::new(),
            protected: Vec::new(),
            mode: None,
            audit: None,
            broker: true,
            enabled: None,
            target: Vec::new(),
        }
    }
}

/// Outcome of parsing the command line.
#[derive(Debug)]
enum ParseError {
    Help,
    Version,
    Message(String),
}

/// What startup should do with the compiled policy.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Startup {
    /// Apply the backend, start the broker, and exec confined.
    Isolate,
    /// Exec without a sandbox, printing `reason`.
    Unconfined(String),
}

pub fn main() {
    let args = match parse_args(std::env::args_os().skip(1)) {
        Ok(args) => args,
        Err(ParseError::Help) => {
            println!("{HELP}");
            return;
        }
        Err(ParseError::Version) => {
            println!("rpi-sandbox {}", env!("CARGO_PKG_VERSION"));
            return;
        }
        Err(ParseError::Message(message)) => {
            eprintln!("rpi-sandbox: {message}\n\n{HELP}");
            std::process::exit(2);
        }
    };

    if let Err(message) = launch(args) {
        eprintln!("rpi-sandbox: {message}");
        std::process::exit(1);
    }
}

fn launch(args: Args) -> Result<(), String> {
    if args.target.is_empty() {
        return Err("no command to run; use `rpi-sandbox [options] -- rpi ...`".to_string());
    }
    let cwd = std::env::current_dir()
        .map_err(|error| format!("cannot determine the working directory: {error}"))?;
    let (policy, config_path) = build_policy(&args, &cwd)?;

    if let Some(reason) = maintenance_bypass(&args.target) {
        eprintln!("sandbox: bypassed ({reason})");
        return exec_target(&args, false, None, config_path.as_deref());
    }

    match startup_action(&policy, &probe())? {
        Startup::Unconfined(reason) => {
            if policy.enabled && policy.mode != SandboxMode::Off {
                eprintln!("sandbox: {reason}; running without isolation");
            }
            return exec_target(&args, false, None, config_path.as_deref());
        }
        Startup::Isolate => {}
    }

    let socket = if args.broker && policy.approval.is_enabled() {
        match BrokerSocket::bind() {
            Ok(socket) => Some(socket),
            Err(error) => {
                if policy.mode == SandboxMode::Required {
                    return Err(format!("cannot start the approval broker: {error}"));
                }
                eprintln!("warning: {error}; approvals are unavailable");
                None
            }
        }
    } else {
        None
    };

    let socket = match socket {
        Some(socket) => {
            // SAFETY: the launcher is still single-threaded here, so the child
            // only inherits the state created above. The parent never returns.
            let pid = unsafe { libc::fork() };
            if pid < 0 {
                let _ = std::fs::remove_file(&socket.path);
                return Err(format!(
                    "cannot fork the approval broker: {}",
                    std::io::Error::last_os_error()
                ));
            }
            if pid == 0 {
                // Agent side: close our copy of the listener but keep the path
                // for the environment; the broker owns the bound socket.
                let path = socket.release();
                Some(path)
            } else {
                supervise(socket, pid, &policy, &args.profile);
            }
        }
        None => None,
    };

    // Agent side: apply Landlock after the fork and before exec so the broker
    // stays unconfined and the domain covers every future thread and child.
    match linux::plan(&policy).and_then(|plan| linux::apply(&plan)) {
        Ok(()) => exec_target(&args, true, socket.as_deref(), config_path.as_deref()),
        Err(error) => {
            if policy.mode == SandboxMode::Required {
                return Err(format!("cannot apply the filesystem sandbox: {error}"));
            }
            eprintln!("warning: {error}; running without a sandbox");
            exec_target(&args, false, None, config_path.as_deref())
        }
    }
}

fn parse_args<I: Iterator<Item = OsString>>(args: I) -> Result<Args, ParseError> {
    let mut parsed = Args::default();
    let mut iter = args;
    while let Some(arg) = iter.next() {
        let text = arg.to_string_lossy().into_owned();
        if text == "--" {
            parsed.target = iter
                .map(|value| value.to_string_lossy().into_owned())
                .collect();
            if parsed.target.is_empty() {
                return Err(ParseError::Message(
                    "expected a command after `--`".to_string(),
                ));
            }
            return Ok(parsed);
        }
        let mut value = |name: &str| -> Result<String, ParseError> {
            iter.next()
                .map(|value| value.to_string_lossy().into_owned())
                .ok_or_else(|| ParseError::Message(format!("{name} requires a value")))
        };
        match text.as_str() {
            "-h" | "--help" => return Err(ParseError::Help),
            "-V" | "--version" => return Err(ParseError::Version),
            "--profile" => parsed.profile = value("--profile")?,
            "--config" => parsed.config = Some(PathBuf::from(value("--config")?)),
            "--write" => parsed.writable.push(value("--write")?),
            "--protect" => parsed.protected.push(value("--protect")?),
            "--mode" => {
                let mode = value("--mode")?;
                parsed.mode = Some(match mode.as_str() {
                    "auto" => SandboxMode::Auto,
                    "required" => SandboxMode::Required,
                    "off" => SandboxMode::Off,
                    other => {
                        return Err(ParseError::Message(format!(
                            "unknown mode `{other}`; expected auto, required, or off"
                        )))
                    }
                });
            }
            "--audit" => parsed.audit = Some(PathBuf::from(value("--audit")?)),
            "--no-broker" => parsed.broker = false,
            "--broker" => parsed.broker = true,
            "--no-sandbox" => parsed.enabled = Some(false),
            "--sandbox" => parsed.enabled = Some(true),
            other if other.starts_with('-') => {
                return Err(ParseError::Message(format!("unknown option `{other}`")))
            }
            other => {
                return Err(ParseError::Message(format!(
                    "unexpected argument `{other}`; pass the command after `--`"
                )))
            }
        }
    }
    Err(ParseError::Message(
        "missing `--` and the command to run".to_string(),
    ))
}

fn maintenance_bypass(target: &[String]) -> Option<&'static str> {
    // `-- <program> <subcommand> ...`: the subcommand is the first argument
    // after the executable. Checking flags would require knowing rpi's entire
    // option grammar; maintenance commands are always first.
    let first = target.get(1)?;
    MAINTENANCE
        .contains(&first.as_str())
        .then_some("maintenance command")
}

fn build_policy(args: &Args, cwd: &Path) -> Result<(SandboxPolicy, Option<PathBuf>), String> {
    let default_config = agent_dir().map(|dir| dir.join("sandbox.json"));
    let config_path = args.config.clone().or(default_config);
    let global = match &config_path {
        Some(path) => {
            if args.config.is_some() && !path.exists() {
                return Err(format!("sandbox settings {} do not exist", path.display()));
            }
            load_settings_file(path)?
        }
        None => None,
    };
    let project = load_settings_file(&cwd.join(".rpi/sandbox.json"))?;

    let enabled = args
        .enabled
        .or_else(env_sandbox_override)
        .or_else(|| global.as_ref().and_then(|settings| settings.enabled))
        // Running the launcher is the explicit opt-in; persisted defaults stay
        // `false` so a plain `rpi` invocation is never sandboxed implicitly.
        .unwrap_or(true);

    let overrides = PolicyOverrides {
        enabled: Some(enabled),
        mode: args.mode,
        writable: args.writable.clone(),
        protected: args.protected.clone(),
        allow_file_writes: Vec::new(),
    };

    let mut auto_writable = vec![cwd.to_path_buf()];
    if let Some(session_dir) = env_session_dir(cwd) {
        auto_writable.push(session_dir);
    }
    if let Some(agent_dir) = agent_dir() {
        auto_writable.push(agent_dir.join("update-check.json"));
        auto_writable.push(agent_dir.join(".resource-lease"));
    }

    let context = PolicyContext::from_env(cwd.to_path_buf());
    let mut policy = compile_policy(
        global.as_ref(),
        project.as_ref(),
        &overrides,
        &context,
        &auto_writable,
    );
    if let Some(audit) = &args.audit {
        policy.audit_log = Some(resolve_against(audit, cwd));
    }
    Ok((policy, config_path))
}

/// Map the policy and probe result to a startup action.
fn startup_action(policy: &SandboxPolicy, support: &SandboxSupport) -> Result<Startup, String> {
    if !policy.enabled || policy.mode == SandboxMode::Off {
        return Ok(Startup::Unconfined("disabled".to_string()));
    }
    for (protected, writable) in policy.nested_protected() {
        let detail = format!(
            "protected path {} is inside writable root {}; the kernel cannot exclude a subtree",
            protected.display(),
            writable.display()
        );
        if policy.mode == SandboxMode::Required {
            return Err(format!("sandbox is required but {detail}"));
        }
        eprintln!("warning: sandbox: {detail}");
    }
    match support {
        SandboxSupport::Supported(_) => Ok(Startup::Isolate),
        SandboxSupport::Unsupported { reason } => {
            if policy.mode == SandboxMode::Required {
                Err(format!(
                    "sandbox is required but cannot be enforced: {reason}"
                ))
            } else {
                Ok(Startup::Unconfined(reason.clone()))
            }
        }
    }
}

fn agent_dir() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("RPI_CODING_AGENT_DIR") {
        return Some(PathBuf::from(dir));
    }
    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".rpi/agent"))
}

fn env_session_dir(cwd: &Path) -> Option<PathBuf> {
    std::env::var_os("RPI_CODING_AGENT_SESSION_DIR")
        .map(PathBuf::from)
        .map(|dir| resolve_against(&dir, cwd))
}

fn env_sandbox_override() -> Option<bool> {
    std::env::var("RPI_SANDBOX")
        .ok()
        .map(|value| sandbox_flag(&value))
}

fn sandbox_flag(value: &str) -> bool {
    !matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "0" | "false" | "off" | "no"
    )
}

fn resolve_against(path: &Path, cwd: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };
    normalize_and_resolve(&absolute)
}

/// Listening socket for the approval broker.
struct BrokerSocket {
    path: PathBuf,
    listener: UnixListener,
}

impl BrokerSocket {
    fn bind() -> std::io::Result<Self> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.subsec_nanos())
            .unwrap_or(0);
        let path =
            std::env::temp_dir().join(format!("rpi-sandbox-{}-{nonce}.sock", std::process::id()));
        // A stale socket from a crashed run must not block us.
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, Permissions::from_mode(0o600))?;
        Ok(Self { path, listener })
    }

    /// Consume the socket without unlinking the path.
    ///
    /// Used by the forked child: it must close its inherited listener but the
    /// broker parent still owns the bound path.
    fn release(mut self) -> PathBuf {
        std::mem::take(&mut self.path)
    }
}

impl Drop for BrokerSocket {
    fn drop(&mut self) {
        if !self.path.as_os_str().is_empty() {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Parent process: serve approvals, reap the agent, and exit with its status.
fn supervise(socket: BrokerSocket, child: libc::pid_t, policy: &SandboxPolicy, profile: &str) -> ! {
    // The child owns terminal input; the broker must outlive Ctrl+C so a
    // still-running agent keeps its approval channel.
    // SAFETY: signal dispositions are process-wide and the broker renders no UI.
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_IGN);
        libc::signal(libc::SIGTERM, libc::SIG_IGN);
    }
    let _ = socket.listener.set_nonblocking(true);

    let mut connected: Option<UnixStream> = None;
    loop {
        if let Some(code) = try_wait(child) {
            drop(socket);
            std::process::exit(code);
        }
        let mut pollfd = libc::pollfd {
            fd: socket.listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `pollfd` is a valid one-element array and the listener fd is
        // owned by `socket`.
        let ready = unsafe { libc::poll(&mut pollfd, 1, 200) };
        if ready > 0 && (pollfd.revents & libc::POLLIN) != 0 {
            match socket.listener.accept() {
                Ok((stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    connected = Some(stream);
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(error) => {
                    eprintln!("warning: sandbox broker accept failed: {error}");
                    break;
                }
            }
        }
    }

    if let Some(stream) = connected {
        let reader = match stream.try_clone() {
            Ok(clone) => BufReader::new(clone),
            Err(error) => {
                eprintln!("warning: sandbox broker cannot read its socket: {error}");
                let code = wait_child(child);
                drop(socket);
                std::process::exit(code);
            }
        };
        let config = BrokerConfig {
            audit: policy.audit_log.clone(),
            backend: Some("landlock".to_string()),
            profile: Some(profile.to_string()),
            ..BrokerConfig::default()
        };
        if let Err(error) = rpi_sandbox_core::serve(reader, stream, config) {
            eprintln!("warning: sandbox broker stopped: {error}");
        }
    }

    let code = wait_child(child);
    drop(socket);
    std::process::exit(code);
}

fn try_wait(child: libc::pid_t) -> Option<i32> {
    let mut status = 0;
    // SAFETY: `status` is a valid out pointer; WNOHANG never blocks.
    let result = unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) };
    (result == child).then(|| exit_code(status))
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

/// Replace the process with the target command.
///
/// When `applied` is false every sandbox variable is removed so the extension
/// cannot mistake an unconfined process for an isolated one.
fn exec_target(
    args: &Args,
    applied: bool,
    socket: Option<&Path>,
    config: Option<&Path>,
) -> Result<(), String> {
    let mut command = Command::new(&args.target[0]);
    command.args(&args.target[1..]);
    for name in [
        env::ACTIVE,
        env::SOCKET,
        env::PROFILE,
        env::VERSION,
        env::CONFIG,
        env::WRITABLE,
        env::PROTECTED,
    ] {
        command.env_remove(name);
    }
    if applied {
        command
            .env(env::ACTIVE, "1")
            .env(env::VERSION, PROTOCOL_VERSION.to_string())
            .env(env::PROFILE, &args.profile);
        if let Some(socket) = socket {
            command.env(env::SOCKET, socket);
        }
        if !args.writable.is_empty() {
            command.env(env::WRITABLE, args.writable.join("\n"));
        }
        if !args.protected.is_empty() {
            command.env(env::PROTECTED, args.protected.join("\n"));
        }
    }
    if let Some(config) = config {
        command.env(env::CONFIG, config);
    }
    let error = command.exec();
    Err(format!("cannot exec {}: {error}", args.target[0]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rpi_sandbox_core::{ApprovalSettings, PathRule};

    fn args(values: &[&str]) -> Result<Args, ParseError> {
        parse_args(values.iter().map(OsString::from))
    }

    fn policy(enabled: bool, mode: SandboxMode) -> SandboxPolicy {
        SandboxPolicy {
            enabled,
            mode,
            writable: Vec::new(),
            protected: Vec::new(),
            allow_file_writes: Vec::new(),
            approval: ApprovalSettings::default(),
            audit_log: None,
        }
    }

    #[test]
    fn parses_documented_options() {
        let parsed = args(&[
            "--profile",
            "work",
            "--write",
            "/srv/data",
            "--write",
            "/tmp/out",
            "--protect",
            "/srv/secrets",
            "--mode",
            "required",
            "--audit",
            "/tmp/audit.jsonl",
            "--no-broker",
            "--",
            "rpi",
            "-p",
            "hello",
        ])
        .unwrap();
        assert_eq!(parsed.profile, "work");
        assert_eq!(parsed.writable, ["/srv/data", "/tmp/out"]);
        assert_eq!(parsed.protected, ["/srv/secrets"]);
        assert_eq!(parsed.mode, Some(SandboxMode::Required));
        assert_eq!(parsed.audit, Some(PathBuf::from("/tmp/audit.jsonl")));
        assert!(!parsed.broker);
        assert_eq!(parsed.target, ["rpi", "-p", "hello"]);
    }

    #[test]
    fn requires_the_separator_and_a_command() {
        assert!(matches!(
            args(&["--profile", "x"]),
            Err(ParseError::Message(_))
        ));
        assert!(matches!(args(&["--"]), Err(ParseError::Message(_))));
        assert!(matches!(args(&["--write"]), Err(ParseError::Message(_))));
    }

    #[test]
    fn unknown_options_fail_closed() {
        assert!(matches!(
            args(&["--allow-everything", "--", "rpi"]),
            Err(ParseError::Message(_))
        ));
    }

    #[test]
    fn maintenance_commands_bypass() {
        for command in MAINTENANCE {
            assert_eq!(
                maintenance_bypass(&["rpi".to_string(), command.to_string()]),
                Some("maintenance command"),
                "{command} must bypass"
            );
        }
        assert_eq!(
            maintenance_bypass(&["rpi".to_string(), "-p".to_string(), "hi".to_string()]),
            None
        );
    }

    #[test]
    fn disabled_policy_is_unconfined() {
        assert_eq!(
            startup_action(&policy(false, SandboxMode::Auto), &probe()).unwrap(),
            Startup::Unconfined("disabled".to_string())
        );
    }

    #[test]
    fn required_fails_without_a_backend() {
        let support = SandboxSupport::Unsupported {
            reason: "no backend".to_string(),
        };
        let error = startup_action(&policy(true, SandboxMode::Required), &support).unwrap_err();
        assert!(error.contains("required"));
    }

    #[test]
    fn auto_warns_without_a_backend() {
        let support = SandboxSupport::Unsupported {
            reason: "no backend".to_string(),
        };
        assert_eq!(
            startup_action(&policy(true, SandboxMode::Auto), &support).unwrap(),
            Startup::Unconfined("no backend".to_string())
        );
    }

    #[test]
    fn required_rejects_nested_protection() {
        let mut restricted = policy(true, SandboxMode::Required);
        restricted.writable = vec![PathRule::Dir(PathBuf::from("/tmp"))];
        restricted.protected = vec![PathRule::Dir(PathBuf::from("/tmp/.ssh"))];
        let support =
            SandboxSupport::Supported(rpi_sandbox_core::SandboxBackend::Landlock { abi: 6 });
        assert!(startup_action(&restricted, &support).is_err());
    }

    #[test]
    fn sandbox_env_flag_accepts_explicit_off_values() {
        for value in ["0", "false", "OFF", "no", " no "] {
            assert!(!sandbox_flag(value), "{value} must disable");
        }
        for value in ["1", "true", "on", "yes"] {
            assert!(sandbox_flag(value), "{value} must enable");
        }
    }
}
