//! Sandbox backend abstraction.
//!
//! A backend turns the platform-neutral [`SandboxPolicy`] into a concrete plan
//! and then launches the target under that plan. The split exists because the
//! three platforms disagree on *when* confinement is applied:
//!
//! | backend | planning | launch |
//! |---|---|---|
//! | Landlock (Linux) | access masks + path rules | fork the broker, apply the domain to this process, `exec` |
//! | MXC (Windows) | read/write/denied path lists | spawn the child in a Microsoft Execution Container, wait |
//! | Seatbelt (macOS, Phase 3) | SBPL text | fork the broker, `sandbox_init`, `execve` |
//!
//! Everything that is *not* platform-specific (CLI, policy compilation, target
//! resolution, extension injection, environment construction, the broker
//! protocol and its approval store) lives above this trait.
//!
//! Backends are selected at compile time: each target only compiles the
//! implementation whose dependencies exist. A backend `launch` may never return
//! (the Unix implementations replace the process); callers must treat the
//! returned code as "the exit status to propagate" rather than "the child
//! exited".

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;

use crate::broker::BrokerConfig;
use crate::policy::SandboxPolicy;
use crate::probe::SandboxSupport;

/// What a backend can actually enforce.
///
/// The policy layer reports intent; this structure says which parts of that
/// intent the kernel can deliver. User-facing warnings (`/sandbox`, launcher
/// startup) are driven by these flags instead of hard-coded Landlock
/// assumptions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BackendCapabilities {
    /// Stable backend name (`landlock`, `windows-mxc`, `seatbelt`, `none`).
    pub name: &'static str,
    /// Whether `readonly` can be subtracted from inside a writable root.
    ///
    /// Landlock is additive, so it cannot. MXC `denied_paths` and Seatbelt
    /// rules can.
    pub can_subtract_readonly: bool,
    /// Whether applying the sandbox mutates persistent state that must be
    /// rolled back (legacy ACL backends). MXC never does.
    pub persistent_side_effects: bool,
    /// Whether the backend needs explicit read roots to start the target.
    pub needs_read_roots: bool,
    /// Whether a writable root that does not exist is fatal (no inode/ACL to
    /// attach the grant to).
    pub missing_root_is_fatal: bool,
}

impl BackendCapabilities {
    /// Capabilities of the explicit "no confinement" backend.
    pub const NONE: BackendCapabilities = BackendCapabilities {
        name: "none",
        can_subtract_readonly: false,
        persistent_side_effects: false,
        needs_read_roots: false,
        missing_root_is_fatal: false,
    };
}

/// Environment mutations the launcher applies to the sandboxed child.
///
/// Order matters: the launcher removes every `RPI_SANDBOX_*` variable first and
/// then sets the ones that apply, so a nested or stale environment can never
/// claim isolation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SandboxEnv {
    entries: Vec<(OsString, Option<OsString>)>,
}

impl SandboxEnv {
    /// Empty mutation set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Baseline: remove every sandbox variable, whatever the caller decides
    /// next. A nested or stale environment can never claim isolation.
    pub fn baseline() -> Self {
        let mut env = Self::new();
        for name in crate::protocol::env::ALL {
            env.remove(name);
        }
        env
    }

    /// Drop every isolation claim while keeping ordinary settings (`CONFIG`).
    ///
    /// Used when a backend fails to apply after the environment was prepared:
    /// the process must not be able to claim it is sandboxed.
    pub fn remove_isolation_claims(&mut self) {
        for name in [
            crate::protocol::env::ACTIVE,
            crate::protocol::env::SOCKET,
            crate::protocol::env::PROFILE,
            crate::protocol::env::VERSION,
            crate::protocol::env::WRITABLE,
            crate::protocol::env::READONLY,
            crate::protocol::env::POLICY,
        ] {
            self.remove(name);
        }
    }

    /// Set `name` to `value`.
    pub fn set(&mut self, name: impl Into<OsString>, value: impl Into<OsString>) {
        self.entries.push((name.into(), Some(value.into())));
    }

    /// Remove `name`.
    pub fn remove(&mut self, name: impl Into<OsString>) {
        self.entries.push((name.into(), None));
    }

    /// Whether nothing is set or removed.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Apply the mutations to a child command.
    pub fn apply(&self, command: &mut Command) {
        for (name, value) in &self.entries {
            match value {
                Some(value) => {
                    command.env(name, value);
                }
                None => {
                    command.env_remove(name);
                }
            }
        }
    }

    /// Fold the mutations into a complete environment block.
    ///
    /// Used by the Windows launcher, which must pass an explicit environment to
    /// `CreateProcessAsUserW` instead of inheriting `std::process::Command`
    /// semantics.
    pub fn overlay(
        &self,
        base: impl IntoIterator<Item = (OsString, OsString)>,
    ) -> Vec<(OsString, OsString)> {
        let mut merged: Vec<(OsString, OsString)> = Vec::new();
        let mut removed: Vec<OsString> = Vec::new();
        for (name, value) in &self.entries {
            if value.is_none() {
                removed.push(name.clone());
            }
        }
        for (name, value) in base {
            if removed.iter().any(|candidate| candidate == &name) {
                continue;
            }
            merged.retain(|(existing, _)| existing != &name);
            merged.push((name, value));
        }
        for (name, value) in &self.entries {
            if let Some(value) = value {
                merged.retain(|(existing, _)| existing != name);
                merged.push((name.clone(), value.clone()));
            }
        }
        merged
    }
}

/// A backend's compiled, ready-to-apply plan.
///
/// Plans are deliberately inspectable: `--print-plan` renders them without
/// touching the system, and tests can build them on any host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BackendPlan {
    /// No confinement (explicit `--no-sandbox`, maintenance bypass, dry run).
    None,
    /// Landlock ruleset (Linux).
    #[cfg(target_os = "linux")]
    Landlock(crate::linux::LandlockPlan),
    /// Windows MXC filesystem policy.
    #[cfg(windows)]
    Mxc(crate::mxc_plan::MxcPlan),
}

impl BackendPlan {
    /// Stable name used in status output and the broker handshake.
    pub fn backend_name(&self) -> &'static str {
        match self {
            Self::None => "none",
            #[cfg(target_os = "linux")]
            Self::Landlock(_) => "landlock",
            #[cfg(windows)]
            Self::Mxc(_) => "windows-mxc",
        }
    }

    /// Human-readable plan lines, for `rpis --print-plan`.
    pub fn describe(&self) -> Vec<String> {
        match self {
            Self::None => vec!["backend: none (no confinement)".to_string()],
            #[cfg(target_os = "linux")]
            Self::Landlock(plan) => {
                let mut lines = vec![format!("backend: landlock (abi {})", plan.abi)];
                for rule in &plan.rules {
                    lines.push(format!(
                        "  allow 0x{:x} {}",
                        rule.access,
                        rule.path.display()
                    ));
                }
                for path in &plan.skipped {
                    lines.push(format!("  skip (missing) {}", path.display()));
                }
                lines
            }
            #[cfg(windows)]
            Self::Mxc(plan) => plan.describe(),
        }
    }
}

/// Everything a backend needs to start the target.
///
/// The launcher fills this in once, so a backend never parses arguments,
/// compiles policy, or injects extensions on its own.
#[derive(Clone, Debug)]
pub struct LaunchSpec {
    /// Target executable (already resolved).
    pub program: PathBuf,
    /// Arguments forwarded to the target.
    pub args: Vec<String>,
    /// Working directory (inherited by the child when the platform allows).
    pub cwd: PathBuf,
    /// Environment mutations to apply on top of the launcher's environment.
    pub env: SandboxEnv,
    /// Compiled policy, for auditing and backend planning.
    pub policy: SandboxPolicy,
    /// Profile label advertised on the broker.
    pub profile: String,
    /// Broker settings, or `None` when approvals are unavailable.
    pub broker: Option<BrokerConfig>,
    /// Extra read roots (Windows only; ignored elsewhere).
    pub read_roots: Vec<PathBuf>,
}

/// One way to confine a process tree.
pub trait SandboxBackend {
    /// What this backend can enforce.
    fn capabilities(&self) -> BackendCapabilities;

    /// Whether the backend can run on this machine right now.
    fn support(&self) -> SandboxSupport {
        crate::probe()
    }

    /// Compile `policy` into this backend's plan.
    fn plan(&self, policy: &SandboxPolicy) -> Result<BackendPlan, String>;

    /// Start the target under the plan and return the exit code to propagate.
    ///
    /// May not return at all when the platform replaces the current process.
    fn launch(&self, plan: &BackendPlan, spec: LaunchSpec) -> Result<i32, String>;
}

/// The explicit "no confinement" backend.
///
/// Used for `--no-sandbox`, maintenance subcommands, and `--print-plan` dry
/// runs. Keeping it a real backend means the honest-isolation invariant is
/// structural: only a backend that truly applied something writes
/// `RPI_SANDBOX_ACTIVE`.
pub struct NoneBackend;

impl SandboxBackend for NoneBackend {
    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities::NONE
    }

    fn support(&self) -> SandboxSupport {
        crate::probe::SandboxSupport::Supported(crate::probe::SandboxBackend::None)
    }

    fn plan(&self, _policy: &SandboxPolicy) -> Result<BackendPlan, String> {
        Ok(BackendPlan::None)
    }

    fn launch(&self, _plan: &BackendPlan, spec: LaunchSpec) -> Result<i32, String> {
        let mut command = Command::new(&spec.program);
        command.args(&spec.args).current_dir(&spec.cwd);
        spec.env.apply(&mut command);
        let status = command
            .status()
            .map_err(|error| format!("cannot start {}: {error}", spec.program.display()))?;
        Ok(status.code().unwrap_or(1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_overlay_removes_then_sets() {
        let base = vec![
            (OsString::from("KEEP"), OsString::from("1")),
            (OsString::from("DROP"), OsString::from("stale")),
        ];
        let mut env = SandboxEnv::new();
        env.remove("DROP");
        env.set("ACTIVE", "1");
        let merged = env.overlay(base);
        assert!(merged.contains(&(OsString::from("KEEP"), OsString::from("1"))));
        assert!(merged.contains(&(OsString::from("ACTIVE"), OsString::from("1"))));
        assert!(!merged.iter().any(|(name, _)| name == "DROP"));
    }

    #[test]
    fn env_overlay_replaces_existing_values() {
        let base = vec![(OsString::from("ACTIVE"), OsString::from("0"))];
        let mut env = SandboxEnv::new();
        env.set("ACTIVE", "1");
        let merged = env.overlay(base);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].1, OsString::from("1"));
    }

    #[test]
    fn none_backend_names_itself() {
        let backend = NoneBackend;
        assert_eq!(backend.capabilities().name, "none");
        assert!(!backend.capabilities().can_subtract_readonly);
        assert_eq!(
            backend.plan(&SandboxPolicy::default()).unwrap(),
            BackendPlan::None
        );
    }
}
