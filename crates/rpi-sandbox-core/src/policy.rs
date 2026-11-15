//! Filesystem sandbox policy: path rules, configuration, and precedence.
//!
//! The policy only describes intent. Enforcement backends (Landlock, Seatbelt,
//! Windows restricted tokens) are applied elsewhere; keeping the model free of
//! platform code makes it unit-testable on every host.
//!
//! Precedence, from strongest to weakest:
//!
//! 1. [`PathRule`] entries in [`SandboxPolicy::protected`] (always read-only);
//! 2. [`PathRule`] entries in [`SandboxPolicy::writable`] (and
//!    [`SandboxPolicy::allow_file_writes`]);
//! 3. everything else is readable but not writable.

use std::path::{Path, PathBuf};

use crate::approval::ApprovalScope;
use crate::path::normalize_and_resolve;

/// Whether the sandbox is disabled, opportunistic, or mandatory.
#[derive(serde::Serialize, serde::Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SandboxMode {
    /// Never apply the sandbox.
    Off,
    /// Apply when the platform supports it; otherwise warn and continue.
    #[default]
    Auto,
    /// Refuse to start when the platform cannot enforce the sandbox.
    Required,
}

/// `sandbox.approval` settings block.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct ApprovalSettings {
    /// Whether out-of-policy writes may prompt for approval. Absent means
    /// "enabled"; a project settings file may only turn this off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Scope preselected in the approval prompt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_scope: Option<ApprovalScope>,
}

impl ApprovalSettings {
    /// Whether approvals are enabled, treating an absent value as enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled.unwrap_or(true)
    }

    /// Scope preselected in the prompt (`session` unless configured).
    pub fn scope(&self) -> ApprovalScope {
        self.default_scope.unwrap_or_default()
    }
}

/// The `sandbox` block of `sandbox.json`.
///
/// Unknown fields are ignored so a newer host can add keys without breaking an
/// older parser.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct SandboxSettings {
    /// Master switch. Absent means disabled (upstream default: opt-in).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Whether a missing backend is fatal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<SandboxMode>,
    /// Extra writable paths. Project settings may not add entries here.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub writable: Vec<String>,
    /// Paths that stay read-only even when a writable rule covers them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protected: Vec<String>,
    /// Individual files that may always be written (for example `/dev/null`).
    #[serde(
        default,
        alias = "allow_file_writes",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub allow_file_writes: Vec<String>,
    /// Approval prompt behavior.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<ApprovalSettings>,
    /// Where the broker appends denied/approved operations.
    #[serde(default, alias = "audit_log", skip_serializing_if = "Option::is_none")]
    pub audit_log: Option<String>,
}

/// One compiled allow/deny rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathRule {
    /// A directory and everything below it.
    Dir(PathBuf),
    /// Exactly one file.
    File(PathBuf),
}

impl PathRule {
    /// Whether `path` (already normalized) matches this rule.
    pub fn matches(&self, path: &Path) -> bool {
        match self {
            Self::Dir(root) => path == root || path.starts_with(root),
            Self::File(file) => path == file,
        }
    }

    /// The rule's root path.
    pub fn path(&self) -> &Path {
        match self {
            Self::Dir(path) | Self::File(path) => path,
        }
    }
}

/// Result of classifying a path against a policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    /// Covered by a writable rule and not protected.
    Writable,
    /// Covered by a protected rule.
    Protected,
    /// Not covered by any rule: readable, not writable.
    ReadOnly,
}

impl Access {
    /// Whether writes are allowed.
    pub fn is_writable(self) -> bool {
        matches!(self, Self::Writable)
    }
}

/// Inputs used to expand configured paths.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyContext {
    /// Project working directory; relative entries resolve against it.
    pub cwd: PathBuf,
    /// User home directory, when known.
    pub home: Option<PathBuf>,
    /// System temporary directory.
    pub temp: PathBuf,
}

impl PolicyContext {
    /// Build a context from the current process environment.
    pub fn from_env(cwd: PathBuf) -> Self {
        let home = std::env::var_os("HOME").map(PathBuf::from);
        let temp = std::env::var_os("TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        Self { cwd, home, temp }
    }
}

/// Explicit command-line overrides. These are user intent and may both widen
/// and disable the policy.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PolicyOverrides {
    /// `--sandbox` / `--no-sandbox`.
    pub enabled: Option<bool>,
    /// `--mode`.
    pub mode: Option<SandboxMode>,
    /// `--write <path>`.
    pub writable: Vec<String>,
    /// `--protect <path>`.
    pub protected: Vec<String>,
    /// `--allow-write-file <path>`.
    pub allow_file_writes: Vec<String>,
}

/// Compiled, platform-independent sandbox policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SandboxPolicy {
    /// Whether enforcement should be attempted.
    pub enabled: bool,
    /// Failure behavior when the platform cannot enforce the policy.
    pub mode: SandboxMode,
    /// Rules that allow writes.
    pub writable: Vec<PathRule>,
    /// Rules that force read-only access.
    pub protected: Vec<PathRule>,
    /// Individual files exempt from the default read-only behavior.
    pub allow_file_writes: Vec<PathRule>,
    /// Approval prompt behavior.
    pub approval: ApprovalSettings,
    /// Audit log destination, when configured.
    pub audit_log: Option<PathBuf>,
}

/// A policy shape in which `protected` cannot be enforced by the kernel.
///
/// Landlock only grants access; it cannot subtract a subtree from a writable
/// directory. The broker still denies these paths, but direct writes from
/// `bash` or other tools inside the writable root can bypass the kernel layer.
/// Surfaces are reported so the launcher can warn (or fail in `required` mode).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProtectionGap {
    /// A protected path is strictly inside a writable directory rule.
    ProtectedInsideWritable {
        /// Protected path.
        protected: PathBuf,
        /// Writable root that covers it.
        writable: PathBuf,
    },
    /// A protected path does not exist yet, so the kernel has nothing to bind.
    MissingProtected {
        /// Protected path.
        path: PathBuf,
    },
    /// An `allowFileWrites` entry is covered by a protected rule.
    AllowFileWriteProtected {
        /// File that would otherwise be writable.
        file: PathBuf,
        /// Protected rule that covers it.
        protected: PathBuf,
    },
}

impl ProtectionGap {
    /// Whether this gap means the kernel cannot enforce `protected`.
    ///
    /// `AllowFileWriteProtected` is excluded: the conflicting rule is dropped
    /// from the Landlock plan, so it is enforced without a bypass.
    pub fn blocks_kernel_enforcement(&self) -> bool {
        matches!(
            self,
            Self::ProtectedInsideWritable { .. } | Self::MissingProtected { .. }
        )
    }

    /// Human-readable explanation used by the launcher and `/sandbox`.
    pub fn describe(&self) -> String {
        match self {
            Self::ProtectedInsideWritable {
                protected,
                writable,
            } => format!(
                "protected path {} is inside writable root {}; the kernel cannot exclude a \
                 subtree, so bash and other tools can still write it directly (only broker \
                 writes are denied)",
                protected.display(),
                writable.display()
            ),
            Self::MissingProtected { path } => format!(
                "protected path {} does not exist; it is not protected until it exists and the \
                 sandbox restarts",
                path.display()
            ),
            Self::AllowFileWriteProtected { file, protected } => format!(
                "allowFileWrites entry {} is covered by protected {} and will not be granted",
                file.display(),
                protected.display()
            ),
        }
    }
}

impl SandboxPolicy {
    /// Classify an absolute or cwd-relative path.
    ///
    /// The path is canonicalized when it exists (or when its parent exists),
    /// so a symlinked target is compared by its real location.
    pub fn classify(&self, path: &Path) -> Access {
        let path = normalize_and_resolve(path);
        if self.protected.iter().any(|rule| rule.matches(&path)) {
            return Access::Protected;
        }
        if self.writable.iter().any(|rule| rule.matches(&path))
            || self
                .allow_file_writes
                .iter()
                .any(|rule| rule.matches(&path))
        {
            return Access::Writable;
        }
        Access::ReadOnly
    }

    /// Convenience wrapper around [`Self::classify`].
    pub fn is_writable(&self, path: &Path) -> bool {
        self.classify(path).is_writable()
    }

    /// Policy shapes the kernel cannot enforce. Empty when `protected` is
    /// entirely outside writable roots and every protected path exists.
    ///
    /// Rules covered by `protected` are filtered out of the Landlock plan, so a
    /// writable rule *under* a protected path is not reported here: removing it
    /// is exact enforcement.
    pub fn protection_gaps(&self) -> Vec<ProtectionGap> {
        let mut gaps: Vec<ProtectionGap> = Vec::new();
        for protected in &self.protected {
            let path = protected.path();
            let writable_root = self
                .writable
                .iter()
                .find(|writable| writable.path() != path && writable.matches(path));
            if !path.exists() {
                if writable_root.is_some() {
                    gaps.push(ProtectionGap::MissingProtected {
                        path: path.to_path_buf(),
                    });
                }
            } else if let Some(writable) = writable_root {
                gaps.push(ProtectionGap::ProtectedInsideWritable {
                    protected: path.to_path_buf(),
                    writable: writable.path().to_path_buf(),
                });
            }
            for file in &self.allow_file_writes {
                if protected.matches(file.path()) {
                    gaps.push(ProtectionGap::AllowFileWriteProtected {
                        file: file.path().to_path_buf(),
                        protected: path.to_path_buf(),
                    });
                }
            }
        }
        let mut unique: Vec<ProtectionGap> = Vec::new();
        for gap in gaps {
            if !unique.contains(&gap) {
                unique.push(gap);
            }
        }
        unique
    }

    /// Protected rules that fall inside a writable directory rule.
    ///
    /// Kept for callers that only need the legacy pair list; prefer
    /// [`Self::protection_gaps`] for user-facing diagnostics.
    pub fn nested_protected(&self) -> Vec<(PathBuf, PathBuf)> {
        self.protection_gaps()
            .into_iter()
            .filter_map(|gap| match gap {
                ProtectionGap::ProtectedInsideWritable {
                    protected,
                    writable,
                } => Some((protected, writable)),
                _ => None,
            })
            .collect()
    }
}

/// Compile global, project, and CLI settings into one policy.
///
/// Merge rules:
///
/// - `enabled`, `mode`, `writable`, `allowFileWrites`, `auditLog` come from the
///   global settings file and the CLI only; **project settings are ignored**
///   for these fields because a repository is untrusted input.
/// - `protected` is additive across global, project, and CLI sources.
/// - Project settings may turn approvals off (tightening) but may not turn
///   them on.
/// - `cwd` and the system temp directory are always writable; callers pass any
///   additional runtime roots (session directory, export target) in
///   `auto_writable`.
pub fn compile_policy(
    global: Option<&SandboxSettings>,
    project: Option<&SandboxSettings>,
    overrides: &PolicyOverrides,
    context: &PolicyContext,
    auto_writable: &[PathBuf],
) -> SandboxPolicy {
    let enabled = overrides
        .enabled
        .or_else(|| global.and_then(|settings| settings.enabled))
        .unwrap_or(false);
    let mode = overrides
        .mode
        .or_else(|| global.and_then(|settings| settings.mode))
        .unwrap_or_default();

    let mut writable = Vec::new();
    if let Some(settings) = global {
        push_dir_rules(&mut writable, &settings.writable, context);
    }
    push_dir_rules(&mut writable, &overrides.writable, context);
    writable.push(PathRule::Dir(normalize_and_resolve(&context.cwd)));
    writable.push(PathRule::Dir(normalize_and_resolve(&context.temp)));
    for root in auto_writable {
        writable.push(auto_rule(root));
    }

    let mut protected = Vec::new();
    if let Some(settings) = global {
        push_dir_rules(&mut protected, &settings.protected, context);
    }
    if let Some(settings) = project {
        push_dir_rules(&mut protected, &settings.protected, context);
    }
    push_dir_rules(&mut protected, &overrides.protected, context);

    let mut allow_file_writes = Vec::new();
    if let Some(settings) = global {
        push_file_rules(&mut allow_file_writes, &settings.allow_file_writes, context);
    }
    push_file_rules(
        &mut allow_file_writes,
        &overrides.allow_file_writes,
        context,
    );

    let mut approval = global
        .and_then(|settings| settings.approval.clone())
        .unwrap_or_default();
    if project
        .and_then(|settings| settings.approval.as_ref())
        .and_then(|approval| approval.enabled)
        == Some(false)
    {
        // A project may only tighten: disable prompts, never enable them.
        approval.enabled = Some(false);
    }

    let audit_log = global
        .and_then(|settings| settings.audit_log.as_deref())
        .and_then(|value| expand_configured_path(value, context));

    dedupe_rules(&mut writable);
    dedupe_rules(&mut protected);
    dedupe_rules(&mut allow_file_writes);

    SandboxPolicy {
        enabled,
        mode,
        writable,
        protected,
        allow_file_writes,
        approval,
        audit_log,
    }
}

/// Automatic roots come from runtime bookkeeping (session dir, agent-dir
/// files) and are not user configuration. Existing regular files become
/// single-file rules so Landlock gets a write/truncate mask it accepts.
fn auto_rule(path: &Path) -> PathRule {
    let normalized = normalize_and_resolve(path);
    match std::fs::metadata(&normalized) {
        Ok(metadata) if metadata.is_file() => PathRule::File(normalized),
        _ => PathRule::Dir(normalized),
    }
}

fn push_dir_rules(target: &mut Vec<PathRule>, values: &[String], context: &PolicyContext) {
    for value in values {
        if let Some(path) = expand_configured_path(value, context) {
            target.push(PathRule::Dir(path));
        }
    }
}

fn push_file_rules(target: &mut Vec<PathRule>, values: &[String], context: &PolicyContext) {
    for value in values {
        if let Some(path) = expand_configured_path(value, context) {
            target.push(PathRule::File(path));
        }
    }
}

/// Drop exact duplicate rules while keeping the first occurrence (and order).
fn dedupe_rules(rules: &mut Vec<PathRule>) {
    let mut seen: Vec<PathRule> = Vec::new();
    rules.retain(|rule| {
        if seen.contains(rule) {
            false
        } else {
            seen.push(rule.clone());
            true
        }
    });
}

/// Load one sandbox settings file.
///
/// A missing file is `Ok(None)` so defaults apply; malformed JSON is an error
/// so a broken policy fails closed instead of silently widening access.
pub fn load_settings_file(path: &Path) -> Result<Option<SandboxSettings>, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text)
            .map(Some)
            .map_err(|error| format!("invalid sandbox settings {}: {error}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!(
            "cannot read sandbox settings {}: {error}",
            path.display()
        )),
    }
}

/// Expand `${cwd}`, `${home}`, `${tmp}`, and a leading `~`, then resolve
/// relative paths against the project directory.
///
/// Returns `None` for empty values and for `${home}` when the home directory is
/// unknown.
pub fn expand_configured_path(value: &str, context: &PolicyContext) -> Option<PathBuf> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let expanded: PathBuf = if let Some(rest) = value.strip_prefix("${cwd}") {
        join_rest(&context.cwd, rest)
    } else if let Some(rest) = value.strip_prefix("${tmp}") {
        join_rest(&context.temp, rest)
    } else if let Some(rest) = value.strip_prefix("${home}") {
        join_rest(context.home.as_deref()?, rest)
    } else if value == "~" {
        context.home.clone()?
    } else if let Some(rest) = value.strip_prefix("~/") {
        join_rest(context.home.as_deref()?, rest)
    } else {
        PathBuf::from(value)
    };
    let absolute = if expanded.is_absolute() {
        expanded
    } else {
        context.cwd.join(expanded)
    };
    Some(normalize_and_resolve(&absolute))
}

fn join_rest(base: &Path, rest: &str) -> PathBuf {
    let rest = rest.strip_prefix('/').unwrap_or(rest);
    if rest.is_empty() {
        base.to_path_buf()
    } else {
        base.join(rest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::path::lexical_normalize;
    use crate::policy::{
        compile_policy, PolicyContext, PolicyOverrides, SandboxMode, SandboxSettings,
    };

    fn context() -> PolicyContext {
        PolicyContext {
            cwd: PathBuf::from("/work/project"),
            home: Some(PathBuf::from("/home/user")),
            temp: PathBuf::from("/tmp"),
        }
    }

    fn settings(json: &str) -> SandboxSettings {
        serde_json::from_str(json).expect("valid settings")
    }

    #[test]
    fn disabled_by_default() {
        let policy = compile_policy(None, None, &PolicyOverrides::default(), &context(), &[]);
        assert!(!policy.enabled);
        assert_eq!(policy.mode, SandboxMode::Auto);
    }

    #[test]
    fn settings_can_enable() {
        let policy = compile_policy(
            Some(&settings(r#"{"enabled": true}"#)),
            None,
            &PolicyOverrides::default(),
            &context(),
            &[],
        );
        assert!(policy.enabled);
    }

    #[test]
    fn settings_can_disable() {
        let policy = compile_policy(
            Some(&settings(r#"{"enabled": false}"#)),
            None,
            &PolicyOverrides::default(),
            &context(),
            &[],
        );
        assert!(!policy.enabled);
    }

    #[test]
    fn cwd_and_temp_are_always_writable() {
        let policy = compile_policy(
            Some(&settings(r#"{"enabled": true}"#)),
            None,
            &PolicyOverrides::default(),
            &context(),
            &[],
        );
        assert!(policy.is_writable(Path::new("/work/project/src/main.rs")));
        assert!(policy.is_writable(Path::new("/tmp/x")));
        assert!(!policy.is_writable(Path::new("/etc/hosts")));
        assert_eq!(policy.classify(Path::new("/etc/hosts")), Access::ReadOnly);
    }

    #[test]
    fn file_auto_roots_become_file_rules() {
        let dir = tempfile::tempdir().unwrap();
        let lease = dir.path().join("lease");
        std::fs::write(&lease, b"").unwrap();
        let policy = compile_policy(
            Some(&settings(r#"{"enabled": true}"#)),
            None,
            &PolicyOverrides::default(),
            &context(),
            std::slice::from_ref(&lease),
        );
        let normalized = normalize_and_resolve(&lease);
        assert!(
            policy
                .writable
                .iter()
                .any(|rule| matches!(rule, PathRule::File(path) if path == &normalized)),
            "existing auto roots that are files must become file rules"
        );
    }

    #[test]
    fn dir_rules_are_recursive_and_file_rules_are_exact() {
        let dir = PathRule::Dir(PathBuf::from("/data/cache"));
        assert!(dir.matches(Path::new("/data/cache")));
        assert!(dir.matches(Path::new("/data/cache/a/b")));
        assert!(!dir.matches(Path::new("/data/cache-other")));

        let file = PathRule::File(PathBuf::from("/dev/null"));
        assert!(file.matches(Path::new("/dev/null")));
        assert!(!file.matches(Path::new("/dev/null/child")));
    }

    #[test]
    fn protected_wins_over_writable() {
        let policy = compile_policy(
            Some(&settings(
                r#"{
                    "enabled": true,
                    "writable": ["${cwd}"],
                    "protected": ["${cwd}/.rpi/agent"]
                }"#,
            )),
            None,
            &PolicyOverrides::default(),
            &context(),
            &[],
        );
        assert_eq!(
            policy.classify(Path::new("/work/project/src/lib.rs")),
            Access::Writable
        );
        assert_eq!(
            policy.classify(Path::new("/work/project/.rpi/agent/models.json")),
            Access::Protected
        );
    }

    #[test]
    fn project_settings_cannot_add_writable() {
        let policy = compile_policy(
            Some(&settings(r#"{"enabled": true}"#)),
            Some(&settings(r#"{"writable": ["/etc"]}"#)),
            &PolicyOverrides::default(),
            &context(),
            &[],
        );
        assert!(!policy.is_writable(Path::new("/etc/hosts")));
    }

    #[test]
    fn project_settings_cannot_add_file_writes() {
        let policy = compile_policy(
            Some(&settings(r#"{"enabled": true}"#)),
            Some(&settings(r#"{"allowFileWrites": ["/etc/hosts"]}"#)),
            &PolicyOverrides::default(),
            &context(),
            &[],
        );
        assert!(!policy.is_writable(Path::new("/etc/hosts")));
    }

    #[test]
    fn project_settings_cannot_disable() {
        let policy = compile_policy(
            Some(&settings(r#"{"enabled": true}"#)),
            Some(&settings(r#"{"enabled": false, "mode": "off"}"#)),
            &PolicyOverrides::default(),
            &context(),
            &[],
        );
        assert!(policy.enabled);
        assert_eq!(policy.mode, SandboxMode::Auto);
    }

    #[test]
    fn project_settings_cannot_change_audit_log() {
        let policy = compile_policy(
            Some(&settings(
                r#"{"enabled": true, "auditLog": "${home}/audit.jsonl"}"#,
            )),
            Some(&settings(r#"{"auditLog": "/tmp/project-audit.jsonl"}"#)),
            &PolicyOverrides::default(),
            &context(),
            &[],
        );
        assert_eq!(
            policy.audit_log,
            Some(normalize_and_resolve(Path::new("/home/user/audit.jsonl")))
        );
    }

    #[test]
    fn project_settings_can_add_protected() {
        let policy = compile_policy(
            Some(&settings(r#"{"enabled": true}"#)),
            Some(&settings(r#"{"protected": ["${cwd}/secrets"]}"#)),
            &PolicyOverrides::default(),
            &context(),
            &[],
        );
        assert_eq!(
            policy.classify(Path::new("/work/project/secrets/key")),
            Access::Protected
        );
    }

    #[test]
    fn nested_protection_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        let secrets = project.join(".rpi").join("agent");
        std::fs::create_dir_all(&secrets).unwrap();

        let policy = SandboxPolicy {
            enabled: true,
            mode: SandboxMode::Auto,
            writable: vec![PathRule::Dir(normalize_and_resolve(&project))],
            protected: vec![PathRule::Dir(normalize_and_resolve(&secrets))],
            allow_file_writes: Vec::new(),
            approval: ApprovalSettings::default(),
            audit_log: None,
        };
        let nested = policy.nested_protected();
        assert_eq!(nested.len(), 1);
        assert_eq!(nested[0].0, normalize_and_resolve(&secrets));
        assert!(matches!(
            policy.protection_gaps().as_slice(),
            [ProtectionGap::ProtectedInsideWritable { .. }]
        ));
    }

    #[test]
    fn compiled_rules_are_deduplicated() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().to_path_buf();
        let context = PolicyContext {
            cwd: cwd.clone(),
            home: Some(cwd.clone()),
            temp: cwd.clone(),
        };
        let policy = compile_policy(
            Some(&settings(r#"{"enabled": true, "writable": ["${cwd}"]}"#)),
            None,
            &PolicyOverrides::default(),
            &context,
            std::slice::from_ref(&cwd),
        );
        let normalized = normalize_and_resolve(&cwd);
        assert_eq!(
            policy
                .writable
                .iter()
                .filter(|rule| rule.path() == normalized)
                .count(),
            1,
            "cwd must appear exactly once"
        );
    }

    #[test]
    fn protection_gaps_cover_the_unenforceable_shapes() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let secrets = root.join("secrets");
        let nested = root.join("nested");
        std::fs::create_dir_all(&secrets).unwrap();
        std::fs::create_dir_all(nested.join("sub")).unwrap();

        let mut policy = SandboxPolicy {
            enabled: true,
            mode: SandboxMode::Auto,
            writable: vec![PathRule::Dir(normalize_and_resolve(root))],
            protected: vec![PathRule::Dir(normalize_and_resolve(&secrets))],
            allow_file_writes: Vec::new(),
            approval: ApprovalSettings::default(),
            audit_log: None,
        };
        assert!(matches!(
            policy.protection_gaps().as_slice(),
            [ProtectionGap::ProtectedInsideWritable { .. }]
        ));

        // A missing protected path inside writable is not bound by the kernel.
        policy.protected = vec![PathRule::Dir(normalize_and_resolve(&root.join("missing")))];
        assert!(matches!(
            policy.protection_gaps().as_slice(),
            [ProtectionGap::MissingProtected { .. }]
        ));

        // A writable rule under protected is filtered from Landlock, so it is
        // not reported as a gap.
        policy.writable = vec![PathRule::Dir(normalize_and_resolve(&nested.join("sub")))];
        policy.protected = vec![PathRule::Dir(normalize_and_resolve(&nested))];
        assert!(policy.protection_gaps().is_empty());

        // An allowFileWrites entry covered by protected is reported (and
        // filtered from the Landlock plan).
        policy.writable = vec![PathRule::Dir(normalize_and_resolve(root))];
        policy.protected = vec![PathRule::Dir(normalize_and_resolve(&secrets))];
        policy.allow_file_writes =
            vec![PathRule::File(normalize_and_resolve(&secrets.join("key")))];
        assert!(policy
            .protection_gaps()
            .iter()
            .any(|gap| matches!(gap, ProtectionGap::AllowFileWriteProtected { .. })));
        assert!(policy.protection_gaps().iter().all(|gap| {
            !gap.blocks_kernel_enforcement()
                || matches!(gap, ProtectionGap::ProtectedInsideWritable { .. })
        }));
    }

    #[test]
    fn command_line_can_disable() {
        let policy = compile_policy(
            Some(&settings(r#"{"enabled": true}"#)),
            None,
            &PolicyOverrides {
                enabled: Some(false),
                ..PolicyOverrides::default()
            },
            &context(),
            &[],
        );
        assert!(!policy.enabled);
    }

    #[test]
    fn command_line_writable_is_additive() {
        let policy = compile_policy(
            Some(&settings(r#"{"enabled": true}"#)),
            None,
            &PolicyOverrides {
                writable: vec!["/srv/data".to_string()],
                ..PolicyOverrides::default()
            },
            &context(),
            &[],
        );
        assert!(policy.is_writable(Path::new("/srv/data/file")));
    }

    #[test]
    fn expands_placeholders() {
        let ctx = context();
        assert_eq!(
            expand_configured_path("${cwd}/target", &ctx),
            Some(normalize_and_resolve(Path::new("/work/project/target")))
        );
        assert_eq!(
            expand_configured_path("${home}/.ssh", &ctx),
            Some(normalize_and_resolve(Path::new("/home/user/.ssh")))
        );
        assert_eq!(
            expand_configured_path("~/notes", &ctx),
            Some(normalize_and_resolve(Path::new("/home/user/notes")))
        );
        assert_eq!(
            expand_configured_path("${tmp}/rpi", &ctx),
            Some(normalize_and_resolve(Path::new("/tmp/rpi")))
        );
        assert_eq!(expand_configured_path("", &ctx), None);
        assert_eq!(expand_configured_path("   ", &ctx), None);
    }

    #[test]
    fn relative_entries_resolve_against_cwd() {
        let ctx = context();
        assert_eq!(
            expand_configured_path("cache", &ctx),
            Some(normalize_and_resolve(Path::new("/work/project/cache")))
        );
    }

    #[test]
    fn parent_components_are_normalized() {
        let ctx = context();
        assert_eq!(
            expand_configured_path("${cwd}/a/../b", &ctx),
            Some(normalize_and_resolve(Path::new("/work/project/b")))
        );
        assert_eq!(
            lexical_normalize(Path::new("/a/./b/../c")),
            PathBuf::from("/a/c")
        );
    }

    #[test]
    fn unknown_home_skips_home_rules() {
        let ctx = PolicyContext {
            cwd: PathBuf::from("/work"),
            home: None,
            temp: PathBuf::from("/tmp"),
        };
        assert_eq!(expand_configured_path("${home}/.ssh", &ctx), None);
        assert_eq!(expand_configured_path("~/x", &ctx), None);
    }

    #[test]
    fn parses_documented_configuration() {
        let parsed = settings(
            r#"{
                "enabled": true,
                "mode": "required",
                "writable": ["${cwd}", "${tmp}"],
                "protected": ["${home}/.ssh"],
                "allowFileWrites": ["/dev/null"],
                "approval": { "enabled": true, "defaultScope": "once" },
                "auditLog": "${home}/.rpi/audit/sandbox.jsonl"
            }"#,
        );
        assert_eq!(parsed.enabled, Some(true));
        assert_eq!(parsed.mode, Some(SandboxMode::Required));
        assert_eq!(parsed.allow_file_writes, vec!["/dev/null".to_string()]);
        assert_eq!(
            parsed.approval.as_ref().unwrap().default_scope,
            Some(ApprovalScope::Once)
        );
        assert_eq!(
            parsed.audit_log.as_deref(),
            Some("${home}/.rpi/audit/sandbox.jsonl")
        );
    }

    #[test]
    fn project_can_only_disable_approvals() {
        let base = settings(r#"{"enabled": true, "approval": {"enabled": true}}"#);
        let tightened = settings(r#"{"approval": {"enabled": false}}"#);
        let policy = compile_policy(
            Some(&base),
            Some(&tightened),
            &PolicyOverrides::default(),
            &context(),
            &[],
        );
        assert_eq!(policy.approval.enabled, Some(false));

        let loosened = compile_policy(
            Some(&settings(r#"{"enabled": true}"#)),
            Some(&settings(r#"{"approval": {"enabled": true}}"#)),
            &PolicyOverrides::default(),
            &context(),
            &[],
        );
        assert_eq!(loosened.approval.enabled, None);
    }

    #[test]
    fn approval_defaults_when_unset() {
        let approval = ApprovalSettings::default();
        assert!(approval.is_enabled());
        assert_eq!(approval.scope(), ApprovalScope::Session);
    }

    #[test]
    fn settings_files_are_optional_but_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing.json");
        assert_eq!(load_settings_file(&missing).unwrap(), None);

        let valid = dir.path().join("valid.json");
        std::fs::write(&valid, r#"{"enabled": true}"#).unwrap();
        assert_eq!(
            load_settings_file(&valid).unwrap().unwrap().enabled,
            Some(true)
        );

        let broken = dir.path().join("broken.json");
        std::fs::write(&broken, "{").unwrap();
        assert!(load_settings_file(&broken).is_err());
    }

    #[test]
    fn audit_log_is_expanded() {
        let policy = compile_policy(
            Some(&settings(
                r#"{"enabled": true, "auditLog": "${home}/.rpi/audit/sandbox.jsonl"}"#,
            )),
            None,
            &PolicyOverrides::default(),
            &context(),
            &[],
        );
        assert_eq!(
            policy.audit_log,
            Some(normalize_and_resolve(Path::new(
                "/home/user/.rpi/audit/sandbox.jsonl"
            )))
        );
    }

    #[cfg(unix)]
    #[test]
    fn classification_resolves_symlinked_targets() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let allowed = dir.path().join("allowed");
        let outside = dir.path().join("outside");
        std::fs::create_dir(&allowed).unwrap();
        std::fs::create_dir(&outside).unwrap();
        let link = allowed.join("escape");
        symlink(&outside, &link).unwrap();

        let policy = SandboxPolicy {
            enabled: true,
            mode: SandboxMode::Auto,
            writable: vec![PathRule::Dir(normalize_and_resolve(&allowed))],
            protected: Vec::new(),
            allow_file_writes: Vec::new(),
            approval: ApprovalSettings::default(),
            audit_log: None,
        };
        assert!(!policy.is_writable(&link.join("file.txt")));
    }
}
