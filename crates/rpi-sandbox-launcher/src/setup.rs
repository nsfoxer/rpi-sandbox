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
    compile_policy, load_settings_file, normalize_and_resolve, BrokerConfig, PolicyContext,
    PolicyOverrides, SandboxMode, SandboxPolicy, SandboxSupport, PROTOCOL_VERSION,
};

use crate::args::{maintenance_bypass, Args};

/// What startup should do with the compiled policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Startup {
    /// Apply the backend, start the broker, and launch confined.
    Isolate,
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

    let isolate = startup == Startup::Isolate;
    let backend: &dyn SandboxBackend = if isolate {
        platform_backend()
    } else {
        &NoneBackend
    };

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
        if !args.writable.is_empty() {
            sandbox_env.set(env::WRITABLE, args.writable.join("\n"));
        }
        if !args.protected.is_empty() {
            sandbox_env.set(env::PROTECTED, args.protected.join("\n"));
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
            protected: policy.protected.clone(),
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
    for gap in policy.protection_gaps() {
        if !gap.blocks_enforcement(capabilities) {
            // The backend can subtract the subtree (MXC `denied_paths`, Seatbelt).
            continue;
        }
        let detail = gap.describe();
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
    for rule in &policy.protected {
        println!("  protected: {}", rule.path().display());
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
    let name = if cfg!(target_os = "macos") {
        "librpi_sandbox_extension.dylib"
    } else if cfg!(target_os = "windows") {
        "rpi_sandbox_extension.dll"
    } else {
        "librpi_sandbox_extension.so"
    };
    let path = std::env::current_exe().ok()?.parent()?.join(name);
    path.is_file().then_some(path)
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

/// Agent directory (`RPI_CODING_AGENT_DIR`, else `~/.rpi/agent`).
pub fn agent_dir() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("RPI_CODING_AGENT_DIR") {
        return Some(PathBuf::from(dir));
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
            can_subtract_protected: false,
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
    fn required_rejects_nested_protection_without_subtree_denial() {
        let mut restricted = policy(true, SandboxMode::Required);
        restricted.writable = vec![PathRule::Dir(PathBuf::from("/tmp"))];
        restricted.protected = vec![PathRule::Dir(PathBuf::from("/tmp/.ssh"))];
        let support = SandboxSupport::Supported(BackendKind::Landlock { abi: 6 });
        assert!(startup_action(&restricted, caps(), &support).is_err());
    }

    #[test]
    fn a_backend_that_can_subtract_protected_accepts_nested_protection() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join(".ssh");
        std::fs::create_dir(&secret).unwrap();
        let mut restricted = policy(true, SandboxMode::Required);
        restricted.writable = vec![PathRule::Dir(dir.path().to_path_buf())];
        restricted.protected = vec![PathRule::Dir(secret)];
        let mut capabilities = caps();
        capabilities.can_subtract_protected = true;
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
        snapshot.protected = vec![PathRule::File(PathBuf::from("/work/.env"))];
        snapshot.approval = ApprovalSettings::default();
        let encoded = serde_json::to_string(&snapshot).unwrap();
        let decoded: SandboxPolicy = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, snapshot);
    }
}
