//! Versioned launcher/extension wire protocol.
//!
//! Transport is a stream of JSON Lines: one UTF-8 JSON object per line, framed
//! by `\n`. Every request carries a protocol version (`v`) and a client-assigned
//! id that the response echoes. Requests always include an `op` tag; see
//! `docs/protocol.md` for the authoritative description.

use std::io::{self, BufRead};

use serde::{Deserialize, Serialize};

use crate::approval::{ApprovalScope, WriteOp};

/// Current wire protocol version.
pub const PROTOCOL_VERSION: u32 = 1;

/// Default maximum decoded payload size (16 MiB).
pub const DEFAULT_MAX_PAYLOAD: usize = 16 * 1024 * 1024;

/// Environment variables the launcher sets before `exec`.
pub mod env {
    /// `1` when the current process runs inside a launcher-created sandbox.
    pub const ACTIVE: &str = "RPI_SANDBOX_ACTIVE";
    /// Broker socket path (Unix) or named pipe (Windows).
    pub const SOCKET: &str = "RPI_SANDBOX_SOCKET";
    /// Human-readable profile name.
    pub const PROFILE: &str = "RPI_SANDBOX_PROFILE";
    /// Protocol version expected by the broker.
    pub const VERSION: &str = "RPI_SANDBOX_VERSION";
    /// Global settings file the launcher used, so the extension compiles the
    /// same policy.
    pub const CONFIG: &str = "RPI_SANDBOX_CONFIG";
    /// Newline-separated `--write` paths from the launcher.
    pub const WRITABLE: &str = "RPI_SANDBOX_WRITABLE";
    /// Newline-separated `--readonly` paths from the launcher.
    pub const READONLY: &str = "RPI_SANDBOX_READONLY";
    /// Path of the launcher's compiled policy snapshot (JSON).
    ///
    /// The extension prefers this file over re-compiling configuration, so the
    /// kernel boundary and the tool gating can never disagree.
    pub const POLICY: &str = "RPI_SANDBOX_POLICY";
    /// Every variable above, for wholesale removal before re-applying them.
    pub const ALL: [&str; 8] = [
        ACTIVE, SOCKET, PROFILE, VERSION, CONFIG, WRITABLE, READONLY, POLICY,
    ];
}

/// One request frame.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    /// Protocol version; must equal [`PROTOCOL_VERSION`].
    pub v: u32,
    /// Client-assigned id, echoed by the response.
    pub id: u64,
    /// Tagged operation payload.
    #[serde(flatten)]
    pub operation: Operation,
}

impl Request {
    /// Build a request for the current protocol version.
    pub fn new(id: u64, operation: Operation) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            id,
            operation,
        }
    }
}

/// Requested operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Operation {
    /// Handshake: reports client identity and protocol version.
    Hello {
        /// Stable client name.
        client: String,
        /// Client crate version.
        version: String,
    },
    /// Record an approval without performing a write.
    Approve {
        /// Absolute path the approval covers.
        path: String,
        /// Operations covered by the approval.
        operations: Vec<WriteOp>,
        /// Lifetime of the approval.
        scope: ApprovalScope,
        /// Whether the approval covers the subtree below `path`.
        #[serde(default)]
        recursive: bool,
    },
    /// Check whether an approval exists without consuming it.
    Check {
        /// Absolute path to check.
        path: String,
        /// Operation to check.
        operation: WriteOp,
    },
    /// Write or append bytes.
    Write {
        /// Absolute target path.
        path: String,
        /// Base64-encoded payload.
        data: String,
        /// Append instead of replace.
        #[serde(default)]
        append: bool,
    },
    /// Truncate a file.
    Truncate {
        /// Absolute target path.
        path: String,
        /// New length in bytes.
        len: u64,
    },
    /// Delete a file.
    Delete {
        /// Absolute target path.
        path: String,
    },
    /// Rename or move a file.
    Rename {
        /// Absolute source path.
        path: String,
        /// Absolute destination path.
        target: String,
    },
    /// Create a directory and its parents.
    Mkdir {
        /// Absolute directory path.
        path: String,
    },
    /// Drop approvals at `path` (and below it when recursive).
    Revoke {
        /// Absolute path to revoke.
        path: String,
        /// Also drop approvals rooted below `path`.
        #[serde(default)]
        recursive: bool,
    },
}

/// Operation names accepted on the wire.
pub const OPERATION_NAMES: [&str; 9] = [
    "hello", "approve", "check", "write", "truncate", "delete", "rename", "mkdir", "revoke",
];

impl Operation {
    /// Stable name used in audit entries and protocol validation.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Hello { .. } => "hello",
            Self::Approve { .. } => "approve",
            Self::Check { .. } => "check",
            Self::Write { .. } => "write",
            Self::Truncate { .. } => "truncate",
            Self::Delete { .. } => "delete",
            Self::Rename { .. } => "rename",
            Self::Mkdir { .. } => "mkdir",
            Self::Revoke { .. } => "revoke",
        }
    }

    /// Primary path, when the operation has one (used for audit).
    pub fn path(&self) -> Option<&str> {
        match self {
            Self::Hello { .. } => None,
            Self::Approve { path, .. }
            | Self::Check { path, .. }
            | Self::Write { path, .. }
            | Self::Truncate { path, .. }
            | Self::Delete { path, .. }
            | Self::Rename { path, .. }
            | Self::Mkdir { path, .. }
            | Self::Revoke { path, .. } => Some(path),
        }
    }
}

/// One response frame.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Response {
    /// Protocol version of the responder.
    pub v: u32,
    /// Echoed request id.
    pub id: u64,
    /// Whether the operation succeeded.
    pub ok: bool,
    /// Machine-readable error code when `ok` is false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<ErrorCode>,
    /// Human-readable error detail when `ok` is false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Backend name reported by `hello` (for example `landlock`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<String>,
    /// Profile name reported by `hello`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
}

impl Response {
    /// Successful response for `id`.
    pub fn success(id: u64) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            id,
            ok: true,
            code: None,
            error: None,
            sandbox: None,
            profile: None,
        }
    }

    /// Failed response for `id`.
    pub fn failure(id: u64, code: ErrorCode, error: impl Into<String>) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            id,
            ok: false,
            code: Some(code),
            error: Some(error.into()),
            sandbox: None,
            profile: None,
        }
    }

    /// Attach `hello` metadata.
    pub fn with_hello(mut self, backend: Option<String>, profile: Option<String>) -> Self {
        self.sandbox = backend;
        self.profile = profile;
        self
    }
}

/// Machine-readable failure reasons.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// No matching approval.
    NotApproved,
    /// Relative path, escaping `..`, or otherwise unparseable.
    InvalidPath,
    /// Symlink resolution escaped the approved subtree.
    UnsafePath,
    /// Path is read-only by policy; approvals cannot override it.
    ReadOnly,
    /// The active sandbox backend refused the write (`EACCES` / access denied).
    PermissionDenied,
    /// Underlying I/O failure.
    Io,
    /// Frame or payload exceeds the configured limit.
    TooLarge,
    /// Unknown operation or unsupported request.
    Unsupported,
    /// Protocol version mismatch.
    Version,
    /// Broker-internal error (reserved).
    Internal,
    /// Request timed out.
    Timeout,
}

impl ErrorCode {
    /// Stable wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotApproved => "not_approved",
            Self::InvalidPath => "invalid_path",
            Self::UnsafePath => "unsafe_path",
            Self::ReadOnly => "read_only",
            Self::PermissionDenied => "permission_denied",
            Self::Io => "io",
            Self::TooLarge => "too_large",
            Self::Unsupported => "unsupported",
            Self::Version => "version",
            Self::Internal => "internal",
            Self::Timeout => "timeout",
        }
    }
}

/// Broker/client error carrying a protocol error code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrokerError {
    /// Machine-readable reason.
    pub code: ErrorCode,
    /// Human-readable detail.
    pub message: String,
}

impl BrokerError {
    /// Build an error.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for BrokerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for BrokerError {}

/// One frame read from the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    /// Peer closed the stream.
    Eof,
    /// One line without its trailing newline.
    Line(String),
    /// The line exceeded the limit and was discarded.
    TooLarge,
}

/// Read one newline-terminated line, discarding the remainder when it exceeds
/// `limit` bytes so the stream stays framed.
pub fn read_frame<R: BufRead>(reader: &mut R, limit: usize) -> io::Result<Frame> {
    let mut buf: Vec<u8> = Vec::new();
    let mut too_large = false;
    loop {
        let (consumed, found_newline) = {
            let available = reader.fill_buf()?;
            if available.is_empty() {
                if buf.is_empty() && !too_large {
                    return Ok(Frame::Eof);
                }
                break;
            }
            let newline = available.iter().position(|byte| *byte == b'\n');
            let take = newline.unwrap_or(available.len());
            if too_large {
                // Discard the rest of the oversized line.
            } else if buf.len() + take > limit {
                too_large = true;
                buf.clear();
            } else {
                buf.extend_from_slice(&available[..take]);
            }
            (take + usize::from(newline.is_some()), newline.is_some())
        };
        reader.consume(consumed);
        if found_newline {
            break;
        }
    }
    if too_large {
        return Ok(Frame::TooLarge);
    }
    String::from_utf8(buf)
        .map(Frame::Line)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn write_request_matches_the_documented_example() {
        let request = Request::new(
            7,
            Operation::Write {
                path: "/home/u/file.txt".to_string(),
                data: "aGVsbG8=".to_string(),
                append: false,
            },
        );
        let encoded = serde_json::to_string(&request).unwrap();
        assert_eq!(
            encoded,
            r#"{"v":1,"id":7,"op":"write","path":"/home/u/file.txt","data":"aGVsbG8=","append":false}"#
        );
        assert_eq!(serde_json::from_str::<Request>(&encoded).unwrap(), request);
    }

    #[test]
    fn error_response_matches_the_documented_example() {
        let response = Response::failure(
            7,
            ErrorCode::NotApproved,
            "write to /home/u/file.txt is not approved",
        );
        let encoded = serde_json::to_string(&response).unwrap();
        assert_eq!(
            encoded,
            r#"{"v":1,"id":7,"ok":false,"code":"not_approved","error":"write to /home/u/file.txt is not approved"}"#
        );
        assert_eq!(
            serde_json::from_str::<Response>(&encoded).unwrap(),
            response
        );
    }

    #[test]
    fn successful_response_omits_optional_fields() {
        let response = Response::success(7);
        assert_eq!(
            serde_json::to_string(&response).unwrap(),
            r#"{"v":1,"id":7,"ok":true}"#
        );
    }

    #[test]
    fn hello_round_trips() {
        let request = Request::new(
            1,
            Operation::Hello {
                client: "rpi-sandbox-extension".to_string(),
                version: "0.1.0".to_string(),
            },
        );
        let encoded = serde_json::to_string(&request).unwrap();
        assert_eq!(
            encoded,
            r#"{"v":1,"id":1,"op":"hello","client":"rpi-sandbox-extension","version":"0.1.0"}"#
        );
        assert_eq!(serde_json::from_str::<Request>(&encoded).unwrap(), request);
    }

    #[test]
    fn every_operation_round_trips() {
        let operations = vec![
            Operation::Approve {
                path: "/home/u/.ssh".to_string(),
                operations: vec![WriteOp::Create, WriteOp::Overwrite],
                scope: ApprovalScope::Session,
                recursive: false,
            },
            Operation::Check {
                path: "/home/u/a.txt".to_string(),
                operation: WriteOp::Overwrite,
            },
            Operation::Write {
                path: "/home/u/a.txt".to_string(),
                data: "aGVsbG8=".to_string(),
                append: true,
            },
            Operation::Truncate {
                path: "/home/u/a.txt".to_string(),
                len: 0,
            },
            Operation::Delete {
                path: "/home/u/a.txt".to_string(),
            },
            Operation::Rename {
                path: "/home/u/a.txt".to_string(),
                target: "/home/u/b.txt".to_string(),
            },
            Operation::Mkdir {
                path: "/home/u/newdir".to_string(),
            },
            Operation::Revoke {
                path: "/home/u/a.txt".to_string(),
                recursive: true,
            },
        ];
        for (id, operation) in operations.into_iter().enumerate() {
            let request = Request::new(id as u64, operation);
            let encoded = serde_json::to_string(&request).unwrap();
            assert_eq!(serde_json::from_str::<Request>(&encoded).unwrap(), request);
            assert!(encoded.contains("\"op\":"));
        }
    }

    #[test]
    fn responses_round_trip_with_hello_metadata() {
        let response = Response::success(1)
            .with_hello(Some("landlock".to_string()), Some("default".to_string()));
        let encoded = serde_json::to_string(&response).unwrap();
        assert_eq!(
            encoded,
            r#"{"v":1,"id":1,"ok":true,"sandbox":"landlock","profile":"default"}"#
        );
        assert_eq!(
            serde_json::from_str::<Response>(&encoded).unwrap(),
            response
        );
    }

    #[test]
    fn operation_names_cover_every_variant() {
        assert_eq!(OPERATION_NAMES.len(), 9);
        for name in OPERATION_NAMES {
            assert!(!name.is_empty());
        }
    }

    #[test]
    fn frames_split_on_newlines() {
        let mut input = Cursor::new(b"{\"a\":1}\n{\"b\":2}\n".to_vec());
        assert_eq!(
            read_frame(&mut input, 1024).unwrap(),
            Frame::Line("{\"a\":1}".to_string())
        );
        assert_eq!(
            read_frame(&mut input, 1024).unwrap(),
            Frame::Line("{\"b\":2}".to_string())
        );
        assert_eq!(read_frame(&mut input, 1024).unwrap(), Frame::Eof);
    }

    #[test]
    fn last_line_without_newline_is_still_a_frame() {
        let mut input = Cursor::new(b"{\"a\":1}".to_vec());
        assert_eq!(
            read_frame(&mut input, 1024).unwrap(),
            Frame::Line("{\"a\":1}".to_string())
        );
        assert_eq!(read_frame(&mut input, 1024).unwrap(), Frame::Eof);
    }

    #[test]
    fn oversized_frames_are_dropped_but_stream_stays_framed() {
        let mut input = Cursor::new(b"aaaaaaaaaa\nok\n".to_vec());
        assert_eq!(read_frame(&mut input, 4).unwrap(), Frame::TooLarge);
        assert_eq!(
            read_frame(&mut input, 4).unwrap(),
            Frame::Line("ok".to_string())
        );
    }

    #[test]
    fn env_variables_match_the_documented_names() {
        assert_eq!(env::ACTIVE, "RPI_SANDBOX_ACTIVE");
        assert_eq!(env::SOCKET, "RPI_SANDBOX_SOCKET");
        assert_eq!(env::PROFILE, "RPI_SANDBOX_PROFILE");
        assert_eq!(env::VERSION, "RPI_SANDBOX_VERSION");
        assert_eq!(env::CONFIG, "RPI_SANDBOX_CONFIG");
        assert_eq!(env::WRITABLE, "RPI_SANDBOX_WRITABLE");
        assert_eq!(env::READONLY, "RPI_SANDBOX_READONLY");
        assert_eq!(PROTOCOL_VERSION, 1);
    }
}
