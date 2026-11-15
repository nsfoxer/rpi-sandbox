//! Filesystem-sandbox core for `rpi`.
//!
//! The design keeps four concerns separate so they can ship incrementally:
//!
//! - [`policy`] is platform-neutral: rules, expansion, precedence, and the
//!   global/project/CLI merge. It never touches the kernel and is unit-tested
//!   on every host.
//! - [`protocol`] is the versioned wire contract between the extension and the
//!   broker.
//! - [`broker`] owns approvals, performs authorized writes, and appends audit
//!   records. It runs outside the sandbox.
//! - [`probe`] reports what the current platform can enforce, and [`linux`]
//!   contains the Landlock planner/applier.
//!
//! This crate deliberately has no dependency on any `rpi-*` crate: it is the
//! platform and policy layer, not part of the host.

#![warn(missing_docs)]

pub mod approval;
pub mod broker;
pub mod path;
pub mod policy;
pub mod probe;
pub mod protocol;

#[cfg(target_os = "linux")]
pub mod linux;

pub use approval::{
    ApprovalDecision, ApprovalError, ApprovalOption, ApprovalRequest, ApprovalScope, WriteOp,
};
pub use broker::{serve, ApprovalStore, BrokerConfig};
#[cfg(unix)]
pub use broker::{BrokerClient, Hello, WriteBroker};
pub use path::{absolute_lexical, has_nul, lexical_normalize, normalize_and_resolve};
pub use policy::{
    compile_policy, expand_configured_path, load_settings_file, Access, ApprovalSettings, PathRule,
    PolicyContext, PolicyOverrides, SandboxMode, SandboxPolicy, SandboxSettings,
};
pub use probe::{probe, SandboxBackend, SandboxSupport};
#[cfg(unix)]
pub use protocol::BrokerError;
pub use protocol::{
    read_frame, ErrorCode, Frame, Operation, Request, Response, DEFAULT_MAX_PAYLOAD,
    OPERATION_NAMES, PROTOCOL_VERSION,
};
