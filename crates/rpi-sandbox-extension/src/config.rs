//! Extension configuration and effective policy.
//!
//! The extension compiles the same files the launcher used (the launcher
//! exports its global config path as `RPI_SANDBOX_CONFIG`), plus the project
//! file, which can only tighten. The compiled policy is advisory for tool
//! gating; the kernel boundary still comes from the launcher.

use std::path::{Path, PathBuf};

use rpi_sandbox_core::protocol::env as protocol_env;
use rpi_sandbox_core::{
    compile_policy, load_settings_file, normalize_and_resolve, PolicyContext, PolicyOverrides,
    SandboxPolicy, SandboxSettings,
};

/// Effective extension state.
#[derive(Clone, Debug)]
pub struct Config {
    /// Whether the launcher established the kernel boundary.
    pub isolated: bool,
    /// Broker socket advertised by the launcher.
    pub socket: Option<PathBuf>,
    /// Profile label.
    pub profile: String,
    /// Global settings file, when one was found.
    pub config_path: Option<PathBuf>,
    /// Project working directory.
    pub cwd: PathBuf,
    /// Compiled policy.
    pub policy: SandboxPolicy,
}

impl Config {
    /// Read the environment and compile the effective policy.
    pub fn from_env(cwd: &Path) -> Self {
        let isolated = std::env::var(protocol_env::ACTIVE)
            .map(|value| value.trim() == "1")
            .unwrap_or(false);
        let socket = std::env::var_os(protocol_env::SOCKET).map(PathBuf::from);
        let profile =
            std::env::var(protocol_env::PROFILE).unwrap_or_else(|_| "default".to_string());
        let config_path = std::env::var_os(protocol_env::CONFIG)
            .map(PathBuf::from)
            .or_else(|| agent_dir().map(|dir| dir.join("sandbox.json")));

        let global = config_path
            .as_deref()
            .and_then(|path| match load_settings_file(path) {
                Ok(settings) => settings,
                Err(error) => {
                    eprintln!("warning: sandbox: {error}; ignoring the global policy");
                    None
                }
            });
        let project = match load_settings_file(&cwd.join(".rpi/sandbox.json")) {
            Ok(settings) => settings,
            Err(error) => {
                eprintln!("warning: sandbox: {error}; ignoring the project policy");
                None
            }
        };

        let writable = env_list(protocol_env::WRITABLE);
        let protected = env_list(protocol_env::PROTECTED);
        let policy = compile(
            global.as_ref(),
            project.as_ref(),
            isolated,
            cwd,
            &writable,
            &protected,
            session_dir(),
            agent_dir(),
        );
        Self {
            isolated,
            socket,
            profile,
            config_path,
            cwd: cwd.to_path_buf(),
            policy,
        }
    }

    /// Human-readable status used by `SetStatus` and `/sandbox`.
    pub fn status_label(&self) -> String {
        if self.isolated {
            format!("🔒 sandbox ({})", self.profile)
        } else {
            "🔓 not isolated".to_string()
        }
    }

    /// Multi-line description for `/sandbox`.
    pub fn describe(&self) -> String {
        let mut out = format!(
            "sandbox: {}\nprofile: {}\nbroker: {}",
            if self.isolated {
                "isolated (launcher)"
            } else {
                "NOT isolated — run rpi through rpi-sandbox"
            },
            self.profile,
            self.socket
                .as_deref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "unavailable".to_string())
        );
        if let Some(path) = &self.config_path {
            out.push_str(&format!("\nconfig: {}", path.display()));
        }
        out.push_str("\n\nwritable:");
        for rule in &self.policy.writable {
            out.push_str(&format!("\n  {}", rule.path().display()));
        }
        if self.policy.protected.is_empty() {
            out.push_str("\n\nprotected: none");
        } else {
            out.push_str("\n\nprotected:");
            for rule in &self.policy.protected {
                out.push_str(&format!("\n  {}", rule.path().display()));
            }
        }
        let nested = self.policy.nested_protected();
        if !nested.is_empty() {
            out.push_str("\n\nnested (not kernel-enforced):");
            for (protected, writable) in nested {
                out.push_str(&format!(
                    "\n  {} inside {}",
                    protected.display(),
                    writable.display()
                ));
            }
        }
        out
    }
}

/// Compile a policy from optionally loaded files. Shared by `from_env` and
/// tests so project tightening is exercised without touching the environment.
pub fn compile(
    global: Option<&SandboxSettings>,
    project: Option<&SandboxSettings>,
    isolated: bool,
    cwd: &Path,
    writable: &[String],
    protected: &[String],
    session_dir: Option<PathBuf>,
    agent_dir: Option<PathBuf>,
) -> SandboxPolicy {
    let context = PolicyContext::from_env(cwd.to_path_buf());
    let overrides = PolicyOverrides {
        enabled: Some(isolated),
        writable: writable.to_vec(),
        protected: protected.to_vec(),
        ..PolicyOverrides::default()
    };
    let mut auto_writable = vec![cwd.to_path_buf()];
    if let Some(dir) = session_dir {
        auto_writable.push(dir);
    }
    if let Some(dir) = agent_dir {
        auto_writable.push(dir.join("update-check.json"));
        auto_writable.push(dir.join(".resource-lease"));
    }
    compile_policy(global, project, &overrides, &context, &auto_writable)
}

/// Resolve a tool-supplied path against the working directory.
pub fn resolve_tool_path(cwd: &Path, raw: &str) -> PathBuf {
    let path = Path::new(raw);
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };
    normalize_and_resolve(&absolute)
}

fn agent_dir() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("RPI_CODING_AGENT_DIR") {
        return Some(PathBuf::from(dir));
    }
    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".rpi/agent"))
}

fn session_dir() -> Option<PathBuf> {
    std::env::var_os("RPI_CODING_AGENT_SESSION_DIR").map(PathBuf::from)
}

fn env_list(name: &str) -> Vec<String> {
    std::env::var(name)
        .map(|value| {
            value
                .split('\n')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(json: &str) -> SandboxSettings {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn project_settings_only_tighten() {
        let global = settings(r#"{"enabled": true, "writable": ["/srv/data"]}"#);
        let project = settings(
            r#"{"enabled": false, "mode": "off", "writable": ["/etc"], "protected": ["${cwd}/secrets"]}"#,
        );
        let policy = compile(
            Some(&global),
            Some(&project),
            true,
            Path::new("/work/project"),
            &[],
            &[],
            None,
            None,
        );
        assert!(policy.enabled);
        assert_eq!(policy.mode, rpi_sandbox_core::SandboxMode::Auto);
        assert!(policy.is_writable(Path::new("/srv/data/file")));
        assert!(!policy.is_writable(Path::new("/etc/hosts")));
        assert_eq!(
            policy.classify(Path::new("/work/project/secrets/key")),
            rpi_sandbox_core::Access::Protected
        );
    }

    #[test]
    fn launcher_cli_overrides_are_applied() {
        let policy = compile(
            None,
            None,
            true,
            Path::new("/work"),
            &["/srv/data".to_string()],
            &["/work/secrets".to_string()],
            None,
            None,
        );
        assert!(policy.is_writable(Path::new("/srv/data/file")));
        assert_eq!(
            policy.classify(Path::new("/work/secrets/key")),
            rpi_sandbox_core::Access::Protected
        );
    }

    #[test]
    fn extension_policy_is_disabled_without_the_launcher() {
        let policy = compile(None, None, false, Path::new("/work"), &[], &[], None, None);
        assert!(!policy.enabled);
    }

    #[test]
    fn status_labels_are_honest_about_isolation() {
        let isolated = Config {
            isolated: true,
            socket: None,
            profile: "work".to_string(),
            config_path: None,
            cwd: PathBuf::from("/work"),
            policy: compile(None, None, true, Path::new("/work"), &[], &[], None, None),
        };
        assert!(isolated.status_label().contains("🔒"));
        assert!(isolated.describe().contains("isolated (launcher)"));

        let plain = Config {
            isolated: false,
            ..isolated
        };
        assert!(plain.status_label().contains("not isolated"));
        assert!(plain.describe().contains("NOT isolated"));
    }
}
