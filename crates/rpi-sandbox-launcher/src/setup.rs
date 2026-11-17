//! Shared launcher pipeline.
//!
//! Everything here is platform-neutral: argument handling, policy compilation,
//! target resolution, extension injection, environment construction, the
//! policy snapshot, and the startup decision. The platform modules
//! (`linux.rs`, `mxc.rs`) only compile a plan and launch the target.

use std::path::{Path, PathBuf};

use rpi_sandbox_core::backend::{
    BackendCapabilities, BackendPlan, LaunchSpec, NoneBackend, SandboxBackend, SandboxEnv,
};
use rpi_sandbox_core::protocol::env;
use rpi_sandbox_core::state::policy_snapshot_path;
use rpi_sandbox_core::{
    compile_policy, load_settings_file, normalize_and_resolve, BrokerConfig, PathRule,
    PolicyContext, PolicyOverrides, ReadOnlyGap, SandboxMode, SandboxPolicy, SandboxSettings,
    SandboxSupport, PROTOCOL_VERSION,
};

use crate::args::{maintenance_bypass, Args};

/// What startup should do with the compiled policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Startup {
    /// Apply the backend, start the broker, and launch confined.
    Isolate,
    /// Apply the backend, but a `readonly` rule cannot be enforced by the
    /// kernel; the extension reports `partial` instead of claiming full
    /// isolation.
    Partial(String),
    /// Launch without a sandbox, printing `reason`.
    Unconfined(String),
}

/// Run the whole pipeline for one invocation.
pub fn run(args: Args) -> Result<i32, String> {
    let cwd = std::env::current_dir()
        .map_err(|error| format!("cannot determine the working directory: {error}"))?;
    let (policy, config_path) = build_policy(&args, &cwd)?;
    // Snapshots are per-run; collect the ones older runs could not remove.
    rpi_sandbox_core::sweep_policy_snapshots(std::time::Duration::from_secs(3600));

    // Platform-only maintenance actions run before anything is applied.
    let rpi = resolve_rpi(args.rpi.as_deref());
    let capabilities = platform_backend().capabilities();
    let read_roots = if capabilities.needs_read_roots {
        collect_read_roots(&rpi, &args, &cwd)
    } else {
        Vec::new()
    };
    let bypass = maintenance_bypass(&args.target);
    let startup = if bypass.is_some() {
        Startup::Unconfined("maintenance command".to_string())
    } else {
        startup_action(&policy, capabilities, &platform_backend().support())?
    };
    if let Some(reason) = bypass {
        eprintln!("sandbox: bypassed ({reason})");
    }

    let isolate = matches!(startup, Startup::Isolate | Startup::Partial(_));
    let backend: &dyn SandboxBackend = if isolate {
        platform_backend()
    } else {
        &NoneBackend
    };

    // The agent directory stays read-only inside the sandbox, and Landlock/MXC
    // bind file rules to existing inodes. Create the bookkeeping placeholders
    // (and an explicitly configured session directory) before compiling the
    // plan; otherwise the rule is skipped and the sandboxed rpi gets EACCES on
    // its first write. `--print-plan` stays side-effect free.
    if isolate && !args.print_plan {
        let agent = agent_dir();
        let session_dir = resolve_session_dir(&args, &cwd, agent.as_deref());
        ensure_runtime_paths(agent.as_deref(), session_dir.as_deref())?;
    }

    let plan = backend.plan(&policy)?;
    if args.print_plan {
        print_plan(&policy, &plan);
        return Ok(0);
    }

    let mut sandbox_env = SandboxEnv::baseline();
    if let Some(config) = config_path.as_deref() {
        sandbox_env.set(env::CONFIG, config.as_os_str());
    }
    if isolate {
        sandbox_env.set(env::ACTIVE, "1");
        sandbox_env.set(env::VERSION, PROTOCOL_VERSION.to_string());
        sandbox_env.set(env::PROFILE, args.profile.as_str());
        if matches!(startup, Startup::Partial(_)) {
            sandbox_env.set(env::PARTIAL, "1");
        }
        if !args.writable.is_empty() {
            sandbox_env.set(env::WRITABLE, args.writable.join("\n"));
        }
        if !args.readonly.is_empty() {
            sandbox_env.set(env::READONLY, args.readonly.join("\n"));
        }
        match write_policy_snapshot(&policy) {
            Ok(path) => sandbox_env.set(env::POLICY, path.into_os_string()),
            Err(error) => eprintln!("warning: sandbox: cannot write the policy snapshot: {error}"),
        }
    }

    let broker = if isolate && args.broker && policy.approval.is_enabled() {
        Some(BrokerConfig {
            audit: policy.audit_log.clone(),
            backend: Some(plan.backend_name().to_string()),
            profile: Some(args.profile.clone()),
            readonly: policy.readonly.clone(),
            ..BrokerConfig::default()
        })
    } else {
        None
    };

    let read_roots = if isolate { read_roots } else { Vec::new() };

    let extension = bundled_extension();
    let target = inject_extension(&args.target, extension.as_deref(), args.no_extension);

    let spec = LaunchSpec {
        program: rpi,
        args: target,
        cwd,
        env: sandbox_env,
        policy,
        profile: args.profile.clone(),
        broker,
        read_roots,
    };
    backend.launch(&plan, spec)
}

/// The backend compiled for this target.
#[cfg(target_os = "linux")]
pub fn platform_backend() -> &'static dyn SandboxBackend {
    &crate::linux::BACKEND
}

/// The backend compiled for this target.
#[cfg(windows)]
pub fn platform_backend() -> &'static dyn SandboxBackend {
    &crate::mxc::BACKEND
}

/// Map the policy, backend capabilities, and probe result to a startup action.
pub fn startup_action(
    policy: &SandboxPolicy,
    capabilities: BackendCapabilities,
    support: &SandboxSupport,
) -> Result<Startup, String> {
    if !policy.enabled || policy.mode == SandboxMode::Off {
        return Ok(Startup::Unconfined("disabled".to_string()));
    }
    // Warn about every gap the kernel cannot enforce. A nested read-only path
    // on an additive backend (Landlock) is the one that changes the startup
    // decision: `required` refuses, `auto` continues but is reported as
    // `partial` rather than claiming full isolation.
    let gaps: Vec<ReadOnlyGap> = policy
        .protection_gaps()
        .into_iter()
        .filter(|gap| gap.blocks_enforcement(capabilities))
        .collect();
    let nested = gaps
        .iter()
        .any(|gap| matches!(gap, ReadOnlyGap::ReadOnlyInsideWritable { .. }));

    if policy.mode == SandboxMode::Required && nested {
        let gap = gaps
            .iter()
            .find(|gap| matches!(gap, ReadOnlyGap::ReadOnlyInsideWritable { .. }))
            .expect("nested gap was just found");
        return Err(format!(
            "sandbox is required but cannot enforce a read-only path: {}",
            gap.describe()
        ));
    }
    for gap in &gaps {
        eprintln!("warning: sandbox: {}", gap.describe());
    }

    match support {
        SandboxSupport::Supported(_) => {
            if nested {
                Ok(Startup::Partial(
                    "read-only rules are not enforced by the kernel".to_string(),
                ))
            } else {
                Ok(Startup::Isolate)
            }
        }
        SandboxSupport::Unsupported { reason } => {
            if policy.mode == SandboxMode::Required {
                Err(format!(
                    "sandbox is required but cannot be enforced: {reason}"
                ))
            } else {
                eprintln!("sandbox: {reason}; running without isolation");
                Ok(Startup::Unconfined(reason.clone()))
            }
        }
    }
}

/// Print the backend plan and the compiled roots without launching anything.
fn print_plan(policy: &SandboxPolicy, plan: &BackendPlan) {
    for line in plan.describe() {
        println!("{line}");
    }
    println!("policy:");
    println!("  enabled: {}", policy.enabled);
    println!("  mode: {:?}", policy.mode);
    for rule in &policy.writable {
        println!("  writable: {:?} {}", rule, rule.path().display());
    }
    for rule in &policy.readonly {
        println!("  readonly: {}", rule.path().display());
    }
    for rule in &policy.allow_file_writes {
        println!("  allowFileWrite: {}", rule.path().display());
    }
}

/// Persist the compiled policy for the extension.
fn write_policy_snapshot(policy: &SandboxPolicy) -> Result<PathBuf, String> {
    rpi_sandbox_core::ensure_state_dir().map_err(|error| {
        format!(
            "cannot create {}: {error}",
            rpi_sandbox_core::state_dir().display()
        )
    })?;
    let path = policy_snapshot_path(rpi_sandbox_core::nonce());
    let json = serde_json::to_string_pretty(policy)
        .map_err(|error| format!("cannot serialize the policy: {error}"))?;
    std::fs::write(&path, json)
        .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
    Ok(path)
}

/// Extra read roots the Windows backend needs to start the target.
fn collect_read_roots(rpi: &Path, args: &Args, cwd: &Path) -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();
    let mut push = |path: PathBuf| {
        if !roots.contains(&path) {
            roots.push(path);
        }
    };
    if let Some(dir) = rpi.parent() {
        if !dir.as_os_str().is_empty() {
            push(resolve_against(dir, cwd));
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            push(resolve_against(dir, cwd));
        }
    }
    if let Some(dir) = agent_dir() {
        push(normalize_and_resolve(&dir));
    }
    for raw in &args.read_roots {
        push(resolve_against(Path::new(raw), cwd));
    }
    roots
}

/// Resolve the rpi executable to launch.
pub fn resolve_rpi(explicit: Option<&Path>) -> PathBuf {
    if let Some(path) = explicit {
        return path.to_path_buf();
    }
    if let Some(path) = std::env::var_os("RPI_SANDBOX_RPI") {
        return PathBuf::from(path);
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            for name in rpi_file_names() {
                let candidate = dir.join(name);
                if is_executable(&candidate) {
                    return candidate;
                }
            }
        }
    }
    PathBuf::from(rpi_file_names()[0])
}

/// Candidate file names for the rpi binary on this platform.
fn rpi_file_names() -> &'static [&'static str] {
    if cfg!(windows) {
        &["rpi.exe"]
    } else {
        &["rpi"]
    }
}

fn is_executable(path: &Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// The extension shipped next to the launcher, if the build produced one.
pub fn bundled_extension() -> Option<PathBuf> {
    let name = extension_file_name();
    // Prefer the installed plugin: rpi loads it from the extension directory,
    // and injecting the copy next to rpis would load two instances (two broker
    // connections; the second fails with ERROR_PIPE_BUSY).
    if let Some(agent) = agent_dir() {
        let installed = agent.join("extensions").join(name);
        if installed.is_file() {
            return None;
        }
    }
    let path = std::env::current_exe().ok()?.parent()?.join(name);
    path.is_file().then_some(path)
}

/// File name of the bundled sandbox extension on this platform.
pub fn extension_file_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "librpi_sandbox_extension.dylib"
    } else if cfg!(target_os = "windows") {
        "rpi_sandbox_extension.dll"
    } else {
        "librpi_sandbox_extension.so"
    }
}

/// Prepend an explicit `--extension` for the bundled cdylib.
///
/// Skipped when the user turned off extensions, loaded their own extension, or
/// disabled auto-loading. This keeps `rpis` a drop-in replacement for `rpi`.
pub fn inject_extension(
    target: &[String],
    extension: Option<&Path>,
    disabled: bool,
) -> Vec<String> {
    let Some(extension) = extension else {
        return target.to_vec();
    };
    if disabled || target_requests_extensions(target) {
        return target.to_vec();
    }
    let mut args = vec![
        "--extension".to_string(),
        extension.to_string_lossy().into_owned(),
    ];
    args.extend_from_slice(target);
    args
}

/// Whether the target command line already decides how extensions are loaded.
///
/// Only "load nothing" suppresses the bundled sandbox extension. Adding another
/// `--extensions-dir` must not silently drop it: the sandbox UI (status,
/// approvals) would disappear even though the kernel boundary is active.
fn target_requests_extensions(target: &[String]) -> bool {
    target.iter().any(|arg| {
        matches!(arg.as_str(), "--no-extensions" | "-ne")
            || arg.starts_with("--extension=")
            || arg == "--extension"
            || arg == "-e"
    })
}

/// Compile the effective policy for this run.
pub fn build_policy(args: &Args, cwd: &Path) -> Result<(SandboxPolicy, Option<PathBuf>), String> {
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
        mode: Some(resolve_mode(args, global.as_ref())),
        writable: args.writable.clone(),
        readonly: args.readonly.clone(),
        allow_file_writes: Vec::new(),
    };

    let agent = agent_dir();
    let mut auto_writable = vec![cwd.to_path_buf()];
    if let Some(session_dir) = resolve_session_dir(args, cwd, agent.as_deref()) {
        auto_writable.push(session_dir);
    }
    if let Some(agent) = &agent {
        auto_writable.push(agent.join("update-check.json"));
        auto_writable.push(agent.join(".resource-lease"));
    }

    let context = PolicyContext::from_env(cwd.to_path_buf());
    let mut policy = compile_policy(
        global.as_ref(),
        project.as_ref(),
        &overrides,
        &context,
        &auto_writable,
    );
    // `auto_rule` decides File vs Dir by looking at the current filesystem, but
    // the bookkeeping files may not exist yet (the launcher creates them just
    // before compiling the backend plan). Force them to file rules: a directory
    // rule on a regular file makes Landlock reject the whole plan with EINVAL.
    force_bookkeeping_file_rules(&mut policy, agent.as_deref());
    if let Some(audit) = &args.audit {
        policy.audit_log = Some(resolve_against(audit, cwd));
    }
    Ok((policy, config_path))
}

/// Force the agent bookkeeping paths to file rules.
///
/// `compile_policy` classifies automatic entries from `std::fs::metadata` at
/// compile time. These two files are created by the launcher after that, so a
/// missing file would be classified as a directory rule; Landlock then rejects
/// the rule on the regular file with `EINVAL` and the whole plan fails.
fn force_bookkeeping_file_rules(policy: &mut SandboxPolicy, agent: Option<&Path>) {
    let Some(agent) = agent else {
        return;
    };
    let bookkeeping = [
        normalize_and_resolve(&agent.join("update-check.json")),
        normalize_and_resolve(&agent.join(".resource-lease")),
    ];
    for rule in &mut policy.writable {
        if bookkeeping.iter().any(|file| rule.path() == file) {
            let path = rule.path().to_path_buf();
            *rule = PathRule::File(path);
        }
    }
}

/// Effective failure mode: CLI, then the global config, then `required`.
///
/// Running the launcher is the explicit opt-in, so a missing backend refuses to
/// start unless the user asked for `auto`.
fn resolve_mode(args: &Args, global: Option<&SandboxSettings>) -> SandboxMode {
    args.mode
        .or_else(|| global.and_then(|settings| settings.mode))
        .unwrap_or(SandboxMode::Required)
}

/// Effective session directory before the built-in default is applied.
///
/// The host precedence is `--session-dir`, then the global `sessionDir`
/// setting, then `RPI_CODING_AGENT_SESSION_DIR`, then `<cwd>/.rpi/sessions`.
/// The default sits under the cwd rule, so only explicit overrides are returned
/// here.
fn resolve_session_dir(args: &Args, cwd: &Path, agent: Option<&Path>) -> Option<PathBuf> {
    session_dir_from_target(&args.target, cwd)
        .or_else(|| settings_session_dir(agent, cwd))
        .or_else(|| env_session_dir(cwd))
}

/// `--session-dir <path>` or `--session-dir=<path>` in the forwarded rpi args.
///
/// The launcher stops parsing at the first unknown argument, so the flag may
/// appear anywhere in `target`. Everything after an explicit `--` is positional
/// and is not treated as a flag.
fn session_dir_from_target(target: &[String], cwd: &Path) -> Option<PathBuf> {
    let mut iter = target.iter();
    while let Some(arg) = iter.next() {
        if arg == "--" {
            break;
        }
        if arg == "--session-dir" {
            return iter
                .next()
                .map(|value| resolve_against(Path::new(value), cwd));
        }
        if let Some(value) = arg.strip_prefix("--session-dir=") {
            return Some(resolve_against(Path::new(value), cwd));
        }
    }
    None
}

/// `sessionDir` from the global settings file, best effort.
///
/// The host accepts `//` line comments in `settings.json`, so a strict parse
/// failure is retried after stripping comments. A malformed or absent file just
/// yields `None`; the default session directory is under the cwd rule anyway.
fn settings_session_dir(agent: Option<&Path>, cwd: &Path) -> Option<PathBuf> {
    let path = agent?.join("settings.json");
    let text = std::fs::read_to_string(path).ok()?;
    let value: serde_json::Value = match serde_json::from_str(&text) {
        Ok(value) => value,
        Err(_) => serde_json::from_str(&strip_line_comments(&text)).ok()?,
    };
    let raw = value.get("sessionDir")?.as_str()?.trim();
    if raw.is_empty() {
        return None;
    }
    Some(resolve_against(Path::new(raw), cwd))
}

/// Remove `//` line comments that are outside a double-quoted string.
///
/// Mirrors the host's settings parser so a commented `settings.json` still
/// yields `sessionDir`.
fn strip_line_comments(text: &str) -> String {
    text.lines()
        .map(|line| match find_line_comment(line) {
            Some(index) => line[..index].to_string(),
            None => line.to_string(),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn find_line_comment(line: &str) -> Option<usize> {
    let mut in_string = false;
    let mut escaped = false;
    for (index, ch) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' if in_string => escaped = true,
            '"' => in_string = !in_string,
            '/' if !in_string && line.as_bytes().get(index + 1) == Some(&b'/') => {
                return Some(index);
            }
            _ => {}
        }
    }
    None
}

/// Create the runtime files and directories the policy grants write access to.
///
/// Landlock and MXC bind file rules to existing inodes. If a file does not
/// exist, its rule is skipped, and the sandboxed rpi cannot create it because
/// the agent directory stays read-only. The launcher runs before the boundary,
/// so it creates empty placeholders here.
fn ensure_runtime_paths(agent: Option<&Path>, session_dir: Option<&Path>) -> Result<(), String> {
    if let Some(agent) = agent {
        for name in [".resource-lease", "update-check.json"] {
            ensure_placeholder(&agent.join(name))?;
        }
    }
    if let Some(dir) = session_dir {
        ensure_directory(dir)?;
    }
    Ok(())
}

/// Create an empty regular file when missing, refusing symlinks and directories.
fn ensure_placeholder(path: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_file() {
                return Ok(());
            }
            return Err(format!(
                "sandbox runtime path {} must be a regular file, not a symlink or directory",
                path.display()
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "cannot inspect sandbox runtime path {}: {error}",
                path.display()
            ))
        }
    }

    let parent = path
        .parent()
        .ok_or_else(|| format!("sandbox runtime path {} has no parent", path.display()))?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
        options.custom_flags(libc::O_NOFOLLOW);
    }
    match options.open(path) {
        Ok(_) => Ok(()),
        // A concurrent launcher created it between the check and the open.
        // Accept only a regular file; never follow a symlink that won the race.
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = std::fs::symlink_metadata(path).map_err(|error| {
                format!(
                    "cannot inspect sandbox runtime path {}: {error}",
                    path.display()
                )
            })?;
            if metadata.file_type().is_file() {
                Ok(())
            } else {
                Err(format!(
                    "sandbox runtime path {} must be a regular file, not a symlink or directory",
                    path.display()
                ))
            }
        }
        Err(error) => Err(format!(
            "cannot create sandbox runtime path {}: {error}",
            path.display()
        )),
    }
}

/// Create a directory (and its parents) before the sandbox is applied.
fn ensure_directory(path: &Path) -> Result<(), String> {
    std::fs::create_dir_all(path)
        .map_err(|error| format!("cannot create {}: {error}", path.display()))?;
    let metadata = std::fs::metadata(path)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    if metadata.is_dir() {
        Ok(())
    } else {
        Err(format!("{} must be a directory", path.display()))
    }
}

/// Agent directory (`RPI_CODING_AGENT_DIR`, else `~/.rpi/agent`).
///
/// The host rejects relative overrides; the launcher does the same and falls
/// back to the home default, so an empty or POSIX-style value cannot silently
/// create `.resource-lease` in the current directory.
pub fn agent_dir() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("RPI_CODING_AGENT_DIR") {
        let path = PathBuf::from(dir);
        if path.is_absolute() {
            return Some(path);
        }
    }
    rpi_sandbox_core::home_dir().map(|home| home.join(".rpi/agent"))
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

#[cfg(test)]
mod tests {
    use super::*;
    use rpi_sandbox_core::probe::SandboxBackend as BackendKind;
    use rpi_sandbox_core::{probe, ApprovalSettings, PathRule};

    fn policy(enabled: bool, mode: SandboxMode) -> SandboxPolicy {
        SandboxPolicy {
            enabled,
            mode,
            ..SandboxPolicy::default()
        }
    }

    fn caps() -> BackendCapabilities {
        BackendCapabilities {
            name: "test",
            can_subtract_readonly: false,
            persistent_side_effects: false,
            needs_read_roots: false,
            missing_root_is_fatal: false,
        }
    }

    #[test]
    fn disabled_policy_is_unconfined() {
        assert_eq!(
            startup_action(&policy(false, SandboxMode::Auto), caps(), &probe()).unwrap(),
            Startup::Unconfined("disabled".to_string())
        );
    }

    #[test]
    fn required_fails_without_a_backend() {
        let support = SandboxSupport::Unsupported {
            reason: "no backend".to_string(),
        };
        let error =
            startup_action(&policy(true, SandboxMode::Required), caps(), &support).unwrap_err();
        assert!(error.contains("required"));
    }

    #[test]
    fn auto_warns_without_a_backend() {
        let support = SandboxSupport::Unsupported {
            reason: "no backend".to_string(),
        };
        assert_eq!(
            startup_action(&policy(true, SandboxMode::Auto), caps(), &support).unwrap(),
            Startup::Unconfined("no backend".to_string())
        );
    }

    #[test]
    fn required_refuses_nested_readonly_without_subtract() {
        let dir = tempfile::tempdir().unwrap();
        let secrets = dir.path().join(".ssh");
        std::fs::create_dir(&secrets).unwrap();
        let mut restricted = policy(true, SandboxMode::Required);
        restricted.writable = vec![PathRule::Dir(dir.path().to_path_buf())];
        restricted.readonly = vec![PathRule::Dir(secrets)];
        let support = SandboxSupport::Supported(BackendKind::Landlock { abi: 6 });
        let error = startup_action(&restricted, caps(), &support).unwrap_err();
        assert!(error.contains("required"), "{error}");
        assert!(error.contains("read-only"), "{error}");
    }

    #[test]
    fn auto_marks_nested_readonly_partial() {
        let dir = tempfile::tempdir().unwrap();
        let secrets = dir.path().join(".ssh");
        std::fs::create_dir(&secrets).unwrap();
        let mut restricted = policy(true, SandboxMode::Auto);
        restricted.writable = vec![PathRule::Dir(dir.path().to_path_buf())];
        restricted.readonly = vec![PathRule::Dir(secrets)];
        let support = SandboxSupport::Supported(BackendKind::Landlock { abi: 6 });
        assert!(matches!(
            startup_action(&restricted, caps(), &support).unwrap(),
            Startup::Partial(_)
        ));
    }

    #[test]
    fn a_backend_that_can_subtract_readonly_accepts_nested_protection() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join(".ssh");
        std::fs::create_dir(&secret).unwrap();
        let mut restricted = policy(true, SandboxMode::Required);
        restricted.writable = vec![PathRule::Dir(dir.path().to_path_buf())];
        restricted.readonly = vec![PathRule::Dir(secret)];
        let mut capabilities = caps();
        capabilities.can_subtract_readonly = true;
        let support = SandboxSupport::Supported(BackendKind::WindowsMxc);
        assert_eq!(
            startup_action(&restricted, capabilities, &support).unwrap(),
            Startup::Isolate
        );
    }

    #[test]
    fn bundled_extension_is_injected_before_rpi_arguments() {
        let target = vec!["-p".to_string(), "hi".to_string()];
        let extension = Path::new("/opt/rpis/librpi_sandbox_extension.so");
        assert_eq!(
            inject_extension(&target, Some(extension), false),
            [
                "--extension",
                "/opt/rpis/librpi_sandbox_extension.so",
                "-p",
                "hi"
            ]
        );
    }

    #[test]
    fn extension_injection_respects_explicit_choices() {
        let target = vec!["-p".to_string()];
        let extension = Path::new("/opt/rpis/librpi_sandbox_extension.so");
        assert_eq!(
            inject_extension(&target, Some(extension), true),
            target,
            "--no-extension disables auto-loading"
        );
        for flag in [
            "--no-extensions",
            "-ne",
            "-e",
            "--extension",
            "--extension=/tmp/x.so",
        ] {
            let with_flag = vec![flag.to_string()];
            assert_eq!(
                inject_extension(&with_flag, Some(extension), false),
                with_flag,
                "{flag} must suppress the bundled extension"
            );
        }
        // An extra scan directory must not drop the sandbox extension.
        let with_dir = vec!["--extensions-dir".to_string(), "/tmp/plugins".to_string()];
        assert_eq!(
            inject_extension(&with_dir, Some(extension), false),
            [
                "--extension",
                "/opt/rpis/librpi_sandbox_extension.so",
                "--extensions-dir",
                "/tmp/plugins"
            ]
        );
        assert_eq!(
            inject_extension(&target, None, false),
            target,
            "no bundled extension means nothing to inject"
        );
    }

    #[test]
    fn explicit_rpi_path_wins() {
        assert_eq!(
            resolve_rpi(Some(Path::new("/custom/rpi"))),
            PathBuf::from("/custom/rpi")
        );
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

    #[test]
    fn policy_snapshot_round_trips() {
        let mut snapshot = policy(true, SandboxMode::Auto);
        snapshot.writable = vec![PathRule::Dir(PathBuf::from("/work"))];
        snapshot.readonly = vec![PathRule::File(PathBuf::from("/work/.env"))];
        snapshot.approval = ApprovalSettings::default();
        let encoded = serde_json::to_string(&snapshot).unwrap();
        let decoded: SandboxPolicy = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, snapshot);
    }

    #[test]
    fn session_dir_flag_is_detected_in_forwarded_args() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path();
        let absolute = cwd.join("sessions");
        let target = vec![
            "--session-dir".to_string(),
            absolute.to_string_lossy().into_owned(),
        ];
        assert_eq!(
            session_dir_from_target(&target, cwd),
            Some(normalize_and_resolve(&absolute))
        );
        assert_eq!(
            session_dir_from_target(&["--session-dir=rel/sessions".to_string()], cwd),
            Some(normalize_and_resolve(&cwd.join("rel/sessions")))
        );
    }

    #[test]
    fn session_dir_after_double_dash_is_positional() {
        let dir = tempfile::tempdir().unwrap();
        let target = vec![
            "-p".to_string(),
            "hi".to_string(),
            "--".to_string(),
            "--session-dir".to_string(),
            dir.path().to_string_lossy().into_owned(),
        ];
        assert_eq!(session_dir_from_target(&target, dir.path()), None);
    }

    #[test]
    fn settings_session_dir_accepts_line_comments() {
        let dir = tempfile::tempdir().unwrap();
        let agent = dir.path().join("agent");
        std::fs::create_dir_all(&agent).unwrap();
        std::fs::write(
            agent.join("settings.json"),
            "{\n  // custom storage\n  \"sessionDir\": \"sessions\"\n}\n",
        )
        .unwrap();
        assert_eq!(
            settings_session_dir(Some(&agent), dir.path()),
            Some(normalize_and_resolve(&dir.path().join("sessions")))
        );
    }

    #[test]
    fn build_policy_adds_an_explicit_session_dir() {
        let dir = tempfile::tempdir().unwrap();
        let session = dir.path().join("sessions");
        let mut args = Args::default();
        args.target = vec![
            "--session-dir".to_string(),
            session.to_string_lossy().into_owned(),
        ];
        let (policy, _) = build_policy(&args, dir.path()).unwrap();
        assert!(
            policy
                .writable
                .iter()
                .any(|rule| rule.path() == normalize_and_resolve(&session)),
            "the forwarded --session-dir must be writable"
        );
    }

    #[test]
    fn runtime_placeholders_are_created_once() {
        let dir = tempfile::tempdir().unwrap();
        let lease = dir.path().join(".resource-lease");
        ensure_placeholder(&lease).unwrap();
        assert!(lease.is_file());
        // A second run must accept the existing regular file.
        ensure_placeholder(&lease).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn runtime_placeholders_refuse_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::write(&target, b"x").unwrap();
        let link = dir.path().join(".resource-lease");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let error = ensure_placeholder(&link).unwrap_err();
        assert!(error.contains("regular file"), "{error}");
    }

    #[test]
    fn runtime_paths_create_agent_files_and_session_dir() {
        let dir = tempfile::tempdir().unwrap();
        let agent = dir.path().join("agent");
        let session = dir.path().join("sessions/nested");
        ensure_runtime_paths(Some(&agent), Some(&session)).unwrap();
        assert!(agent.join(".resource-lease").is_file());
        assert!(agent.join("update-check.json").is_file());
        assert!(session.is_dir());
    }

    #[test]
    fn bookkeeping_paths_become_file_rules_even_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let agent = dir.path().join("agent");
        let mut snapshot = SandboxPolicy::default();
        snapshot.writable = vec![
            PathRule::Dir(normalize_and_resolve(&agent.join(".resource-lease"))),
            PathRule::Dir(normalize_and_resolve(&agent.join("update-check.json"))),
            PathRule::Dir(dir.path().to_path_buf()),
        ];
        force_bookkeeping_file_rules(&mut snapshot, Some(&agent));
        assert!(matches!(&snapshot.writable[0], PathRule::File(_)));
        assert!(matches!(&snapshot.writable[1], PathRule::File(_)));
        assert!(
            matches!(&snapshot.writable[2], PathRule::Dir(_)),
            "ordinary writable roots stay directories"
        );
    }

    #[test]
    fn the_launcher_defaults_to_required() {
        let args = Args::default();
        assert_eq!(resolve_mode(&args, None), SandboxMode::Required);
    }

    #[test]
    fn explicit_modes_win_over_the_required_default() {
        let global = SandboxSettings {
            mode: Some(SandboxMode::Off),
            ..SandboxSettings::default()
        };
        let mut args = Args::default();
        args.mode = Some(SandboxMode::Auto);
        assert_eq!(resolve_mode(&args, Some(&global)), SandboxMode::Auto);
        args.mode = None;
        assert_eq!(resolve_mode(&args, Some(&global)), SandboxMode::Off);
    }
}
