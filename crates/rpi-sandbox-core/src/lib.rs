//! Filesystem-sandbox core for `rpi`.
//!
//! The design keeps the concerns separate so they can ship incrementally:
//!
//! - [`policy`] is platform-neutral: rules, expansion, precedence, and the
//!   global/project/CLI merge. It never touches the kernel and is unit-tested
//!   on every host.
//! - [`backend`] is the seam between policy and enforcement: capabilities,
//!   launch specs, and the [`backend::SandboxBackend`] trait.
//! - [`protocol`] is the versioned wire contract between the extension and the
//!   broker, and [`transport`] carries it over Unix sockets or named pipes.
//! - [`broker`] owns approvals, performs authorized writes, and appends audit
//!   records. It runs outside the sandbox.
//! - [`probe`] reports what the current platform can enforce; [`linux`] holds
//!   the Landlock planner and [`mxc_plan`] the MXC planner.
//!
//! This crate deliberately has no dependency on any `rpi-*` crate: it is the
//! platform and policy layer, not part of the host.

#![warn(missing_docs)]

pub mod approval;
pub mod audit;
pub mod backend;
pub mod broker;
pub mod path;
pub mod policy;
pub mod probe;
pub mod protocol;
pub mod safe_fs;
pub mod state;
pub mod transport;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(windows)]
pub mod mxc_plan;

pub use approval::{
    ApprovalDecision, ApprovalError, ApprovalOption, ApprovalRequest, ApprovalScope, WriteOp,
};
pub use audit::{AuditEvent, AuditLog};
pub use backend::{
    BackendCapabilities, BackendPlan, LaunchSpec, NoneBackend, SandboxBackend, SandboxEnv,
};
pub use broker::{
    serve, ApprovalStore, BrokerClient, BrokerConfig, BrokerService, Hello, WriteBroker,
};
pub use path::{
    absolute_lexical, has_nul, lexical_normalize, normalize_and_resolve, validate_local_path,
};
pub use policy::{
    compile_policy, expand_configured_path, home_dir, home_dir_from, load_settings_file, temp_dir,
    temp_dir_from, Access, ApprovalSettings, PathRule, PolicyContext, PolicyOverrides, ReadOnlyGap,
    SandboxMode, SandboxPolicy, SandboxSettings,
};
pub use probe::{probe, SandboxBackend as SandboxBackendKind, SandboxSupport};
pub use protocol::BrokerError;
pub use protocol::{
    read_frame, ErrorCode, Frame, Operation, Request, Response, DEFAULT_MAX_PAYLOAD,
    OPERATION_NAMES, PROTOCOL_VERSION,
};
pub use state::{ensure_state_dir, nonce, policy_snapshot_path, state_dir, sweep_policy_snapshots};
pub use transport::{Conn, Listener};
