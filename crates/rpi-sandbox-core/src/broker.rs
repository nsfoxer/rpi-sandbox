//! Out-of-process write broker.
//!
//! Kernel sandboxes (Landlock, Seatbelt, Windows restricted tokens) can only
//! narrow permissions, never widen them at runtime. Dynamic approval therefore
//! needs one unconfined helper process: the broker started by the launcher
//! before the sandbox is applied. The sandboxed agent asks the broker to perform
//! an approved write; the broker re-validates the request against its own
//! approval store, re-resolves the path, and is the only component that ever
//! touches a path outside the sandbox.
//!
//! Protocol: one JSON object per line over a Unix stream socket (see
//! [`crate::protocol`]).
//!
//! Known limitation: the broker re-resolves paths before mutating, and applies
//! `O_NOFOLLOW` to the final component on Unix, but a parent directory swapped
//! for a symlink between the check and the write can still redirect the
//! operation. Closing that race requires `openat2(RESOLVE_BENEATH)` or
//! equivalent platform APIs and is tracked as a hardening task.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;

use crate::approval::{ApprovalScope, WriteOp};
use crate::path::{absolute_lexical, normalize_and_resolve};
use crate::protocol::{
    read_frame, BrokerError, ErrorCode, Frame, Operation, Request, Response, DEFAULT_MAX_PAYLOAD,
    OPERATION_NAMES, PROTOCOL_VERSION,
};

/// Where the broker appends one JSON line per handled request.
#[derive(Clone, Debug)]
pub struct BrokerConfig {
    /// Audit log destination. `None` disables logging (not recommended).
    pub audit: Option<PathBuf>,
    /// Backend name reported by `hello` (for example `landlock`).
    pub backend: Option<String>,
    /// Profile name reported by `hello`.
    pub profile: Option<String>,
    /// Maximum decoded payload size, in bytes.
    pub max_payload: usize,
}

impl Default for BrokerConfig {
    fn default() -> Self {
        Self {
            audit: None,
            backend: None,
            profile: None,
            max_payload: DEFAULT_MAX_PAYLOAD,
        }
    }
}

impl BrokerConfig {
    /// Maximum wire line length accepted for one frame.
    fn max_frame(&self) -> usize {
        // Base64 expands by 4/3; keep enough room for the envelope so the
        // decoded limit, not the encoding overhead, is what callers bump into.
        self.max_payload
            .saturating_mul(4)
            .saturating_div(3)
            .saturating_add(4096)
    }
}

#[derive(Clone, Debug)]
struct Entry {
    operations: BTreeSet<WriteOp>,
    scope: ApprovalScope,
    recursive: bool,
}

/// Session-scoped approval store owned by the broker (not the sandboxed agent).
#[derive(Default, Debug)]
pub struct ApprovalStore {
    entries: BTreeMap<PathBuf, Entry>,
}

impl ApprovalStore {
    /// Record an approval. `ops` must be non-empty.
    pub fn approve(&mut self, path: &Path, ops: &[WriteOp], scope: ApprovalScope, recursive: bool) {
        let operations: BTreeSet<WriteOp> = ops.iter().copied().collect();
        if operations.is_empty() {
            return;
        }
        self.entries
            .entry(normalize_and_resolve(path))
            .and_modify(|entry| {
                entry.operations.extend(operations.iter().copied());
                entry.scope = scope;
                entry.recursive |= recursive;
            })
            .or_insert(Entry {
                operations,
                scope,
                recursive,
            });
    }

    /// Revoke approvals at `path` (and every entry below it when `recursive`).
    pub fn revoke(&mut self, path: &Path, recursive: bool) {
        let key = normalize_and_resolve(path);
        if recursive {
            self.entries
                .retain(|root, _| !(root == &key || root.starts_with(&key)));
        } else {
            self.entries.remove(&key);
        }
    }

    /// Whether an approval covers `path` (no consumption).
    pub fn check(&self, path: &Path, operation: WriteOp) -> Option<ApprovalScope> {
        let key = normalize_and_resolve(path);
        if let Some(entry) = self.entries.get(&key) {
            if entry.operations.contains(&operation) {
                return Some(entry.scope);
            }
        }
        self.entries
            .iter()
            .find(|(root, entry)| {
                entry.recursive && entry.operations.contains(&operation) && key.starts_with(root)
            })
            .map(|(_, entry)| entry.scope)
    }

    /// Check and consume one use of an approval.
    pub fn allow(&mut self, path: &Path, operation: WriteOp) -> Option<ApprovalScope> {
        let key = normalize_and_resolve(path);
        let mut matched: Option<(PathBuf, ApprovalScope)> = None;
        if let Some(entry) = self.entries.get(&key) {
            if entry.operations.contains(&operation) {
                matched = Some((key.clone(), entry.scope));
            }
        }
        if matched.is_none() {
            for (root, entry) in &self.entries {
                if entry.recursive && entry.operations.contains(&operation) && key.starts_with(root)
                {
                    matched = Some((root.clone(), entry.scope));
                    break;
                }
            }
        }
        let (key, scope) = matched?;
        if scope == ApprovalScope::Once {
            self.entries.remove(&key);
        }
        Some(scope)
    }

    /// Whether an already-normalized lexical path falls under an approval root.
    ///
    /// Used only to distinguish a symlink escape from a plain missing approval.
    fn covers_lexically(&self, lexical: &Path, operation: WriteOp) -> bool {
        self.entries.iter().any(|(root, entry)| {
            entry.operations.contains(&operation) && (lexical == root || lexical.starts_with(root))
        })
    }
}

/// Serve the broker until the peer closes the connection.
///
/// The broker is single-threaded and processes requests in order, matching the
/// protocol contract. Audit failures never abort a mutation.
pub fn serve<R: BufRead, W: Write>(
    mut reader: R,
    mut writer: W,
    config: BrokerConfig,
) -> std::io::Result<()> {
    let mut store = ApprovalStore::default();
    let mut audit = open_audit(config.audit.as_deref());
    loop {
        match read_frame(&mut reader, config.max_frame())? {
            Frame::Eof => break,
            Frame::TooLarge => {
                let message = format!("request exceeds {} bytes", config.max_payload);
                log_audit(&mut audit, "protocol", "-", false, Some(&message), None);
                write_response(
                    &mut writer,
                    Response::failure(0, ErrorCode::TooLarge, message),
                )?;
            }
            Frame::Line(line) => {
                if line.trim().is_empty() {
                    continue;
                }
                let response = handle_line(&mut store, &line, &config, &mut audit);
                write_response(&mut writer, response)?;
            }
        }
    }
    Ok(())
}

fn write_response<W: Write>(writer: &mut W, response: Response) -> std::io::Result<()> {
    serde_json::to_writer(&mut *writer, &response).map_err(std::io::Error::other)?;
    writeln!(writer)?;
    writer.flush()
}

fn handle_line(
    store: &mut ApprovalStore,
    line: &str,
    config: &BrokerConfig,
    audit: &mut Option<File>,
) -> Response {
    let value: serde_json::Value = match serde_json::from_str(line) {
        Ok(value) => value,
        Err(error) => {
            let message = format!("invalid JSON: {error}");
            log_audit(audit, "protocol", "-", false, Some(&message), None);
            return Response::failure(0, ErrorCode::Internal, message);
        }
    };

    let id = value.get("id").and_then(|id| id.as_u64()).unwrap_or(0);
    let version = value.get("v").and_then(|version| version.as_u64());
    if version != Some(u64::from(PROTOCOL_VERSION)) {
        let message = format!(
            "unsupported protocol version {}; expected {PROTOCOL_VERSION}",
            version.map_or_else(|| "missing".to_string(), |value| value.to_string())
        );
        log_audit(
            audit,
            "protocol",
            json_path(&value),
            false,
            Some(&message),
            None,
        );
        return Response::failure(id, ErrorCode::Version, message);
    }

    let operation_name = value
        .get("op")
        .and_then(|op| op.as_str())
        .map(str::to_string);
    let Some(operation_name) = operation_name else {
        let message = "request is missing the op field".to_string();
        log_audit(
            audit,
            "protocol",
            json_path(&value),
            false,
            Some(&message),
            None,
        );
        return Response::failure(id, ErrorCode::Unsupported, message);
    };
    if !OPERATION_NAMES.contains(&operation_name.as_str()) {
        let message = format!("unknown operation: {operation_name}");
        log_audit(
            audit,
            "protocol",
            json_path(&value),
            false,
            Some(&message),
            None,
        );
        return Response::failure(id, ErrorCode::Unsupported, message);
    }

    let request: Request = match serde_json::from_value(value) {
        Ok(request) => request,
        Err(error) => {
            let message = format!("invalid {operation_name} request: {error}");
            log_audit(audit, "protocol", "-", false, Some(&message), None);
            return Response::failure(id, ErrorCode::Internal, message);
        }
    };
    handle_request(store, request, config, audit)
}

fn json_path(value: &serde_json::Value) -> &str {
    value
        .get("path")
        .and_then(|path| path.as_str())
        .unwrap_or("-")
}

fn handle_request(
    store: &mut ApprovalStore,
    request: Request,
    config: &BrokerConfig,
    audit: &mut Option<File>,
) -> Response {
    let id = request.id;
    let name = request.operation.name();
    let path_label = request.operation.path().unwrap_or("-").to_string();

    if matches!(request.operation, Operation::Hello { .. }) {
        log_audit(audit, name, "-", true, None, None);
        return Response::success(id).with_hello(config.backend.clone(), config.profile.clone());
    }

    match dispatch(store, request.operation, config) {
        Ok(scope) => {
            log_audit(
                audit,
                name,
                &path_label,
                true,
                None,
                scope.map(ApprovalScope::as_str),
            );
            Response::success(id)
        }
        Err(error) => {
            log_audit(audit, name, &path_label, false, Some(&error.message), None);
            Response::failure(id, error.code, error.message)
        }
    }
}

fn dispatch(
    store: &mut ApprovalStore,
    operation: Operation,
    config: &BrokerConfig,
) -> Result<Option<ApprovalScope>, BrokerError> {
    match operation {
        Operation::Hello { .. } => Ok(None),
        Operation::Approve {
            path,
            operations,
            scope,
            recursive,
        } => {
            let (_, resolved) = parse_request_path(&path)?;
            if operations.is_empty() {
                return Err(BrokerError::new(
                    ErrorCode::Internal,
                    "approve requires at least one operation",
                ));
            }
            store.approve(&resolved, &operations, scope, recursive);
            Ok(Some(scope))
        }
        Operation::Check { path, operation } => {
            let (lexical, resolved) = parse_request_path(&path)?;
            let scope = assess(store, &lexical, &resolved, operation)?;
            Ok(scope)
        }
        Operation::Write { path, data, append } => {
            let (lexical, resolved) = parse_request_path(&path)?;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(data.as_bytes())
                .map_err(|error| {
                    BrokerError::new(
                        ErrorCode::Internal,
                        format!("invalid base64 payload: {error}"),
                    )
                })?;
            if bytes.len() > config.max_payload {
                return Err(BrokerError::new(
                    ErrorCode::TooLarge,
                    format!(
                        "payload is {} bytes; the limit is {}",
                        bytes.len(),
                        config.max_payload
                    ),
                ));
            }
            let write_op = if append {
                WriteOp::Append
            } else if resolved.exists() {
                WriteOp::Overwrite
            } else {
                WriteOp::Create
            };
            let scope = authorize(store, &lexical, &resolved, write_op)?;
            write_file(&resolved, &bytes, append)?;
            Ok(Some(scope))
        }
        Operation::Truncate { path, len } => {
            let (lexical, resolved) = parse_request_path(&path)?;
            let scope = authorize(store, &lexical, &resolved, WriteOp::Overwrite)?;
            revalidate(&resolved, &lexical)?;
            let mut options = OpenOptions::new();
            options.write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.custom_flags(libc::O_NOFOLLOW);
            }
            let file = options.open(&resolved).map_err(io_error)?;
            file.set_len(len).map_err(io_error)?;
            Ok(Some(scope))
        }
        Operation::Delete { path } => {
            let (lexical, resolved) = parse_request_path(&path)?;
            let scope = authorize(store, &lexical, &resolved, WriteOp::Delete)?;
            revalidate(&resolved, &lexical)?;
            std::fs::remove_file(&resolved).map_err(io_error)?;
            Ok(Some(scope))
        }
        Operation::Rename { path, target } => {
            let (source_lexical, source) = parse_request_path(&path)?;
            let (target_lexical, destination) = parse_request_path(&target)?;
            let source_scope = authorize(store, &source_lexical, &source, WriteOp::Rename)?;
            authorize(store, &target_lexical, &destination, WriteOp::Create)?;
            revalidate(&source, &source_lexical)?;
            revalidate(&destination, &target_lexical)?;
            if let Some(parent) = destination.parent() {
                if !parent.exists() {
                    std::fs::create_dir_all(parent).map_err(io_error)?;
                }
            }
            std::fs::rename(&source, &destination).map_err(io_error)?;
            Ok(Some(source_scope))
        }
        Operation::Mkdir { path } => {
            let (lexical, resolved) = parse_request_path(&path)?;
            let scope = authorize(store, &lexical, &resolved, WriteOp::Mkdir)?;
            revalidate(&resolved, &lexical)?;
            std::fs::create_dir_all(&resolved).map_err(io_error)?;
            Ok(Some(scope))
        }
        Operation::Revoke { path, recursive } => {
            let (_, resolved) = parse_request_path(&path)?;
            store.revoke(&resolved, recursive);
            Ok(None)
        }
    }
}

/// Parse and normalize an absolute request path.
fn parse_request_path(raw: &str) -> Result<(PathBuf, PathBuf), BrokerError> {
    let lexical = absolute_lexical(Path::new(raw)).ok_or_else(|| {
        BrokerError::new(
            ErrorCode::InvalidPath,
            format!("path must be absolute and must not escape the root: {raw}"),
        )
    })?;
    let resolved = normalize_and_resolve(&lexical);
    Ok((lexical, resolved))
}

/// Consume an approval for `resolved`, distinguishing symlink escapes.
fn authorize(
    store: &mut ApprovalStore,
    lexical: &Path,
    resolved: &Path,
    operation: WriteOp,
) -> Result<ApprovalScope, BrokerError> {
    if let Some(scope) = store.allow(resolved, operation) {
        return Ok(scope);
    }
    if lexical != resolved && store.covers_lexically(lexical, operation) {
        return Err(BrokerError::new(
            ErrorCode::UnsafePath,
            format!(
                "{} resolves outside its approved root ({})",
                lexical.display(),
                resolved.display()
            ),
        ));
    }
    Err(not_approved(operation, resolved))
}

/// Non-consuming variant used by `check`.
fn assess(
    store: &ApprovalStore,
    lexical: &Path,
    resolved: &Path,
    operation: WriteOp,
) -> Result<Option<ApprovalScope>, BrokerError> {
    if let Some(scope) = store.check(resolved, operation) {
        return Ok(Some(scope));
    }
    if lexical != resolved && store.covers_lexically(lexical, operation) {
        return Err(BrokerError::new(
            ErrorCode::UnsafePath,
            format!(
                "{} resolves outside its approved root ({})",
                lexical.display(),
                resolved.display()
            ),
        ));
    }
    Err(not_approved(operation, resolved))
}

fn not_approved(operation: WriteOp, path: &Path) -> BrokerError {
    BrokerError::new(
        ErrorCode::NotApproved,
        format!(
            "{} of {} is not approved",
            operation.as_str(),
            path.display()
        ),
    )
}

/// Re-resolve immediately before mutating so a swapped symlink is detected.
fn revalidate(path: &Path, lexical: &Path) -> Result<(), BrokerError> {
    if &normalize_and_resolve(path) != path {
        return Err(BrokerError::new(
            ErrorCode::UnsafePath,
            format!(
                "{} changed while the request was handled",
                lexical.display()
            ),
        ));
    }
    Ok(())
}

fn write_file(path: &Path, bytes: &[u8], append: bool) -> Result<(), BrokerError> {
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent).map_err(io_error)?;
        }
    }
    revalidate(path, path)?;
    let mut options = OpenOptions::new();
    options.write(true);
    if append {
        options.append(true).create(true);
    } else {
        options.truncate(true).create(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path).map_err(io_error)?;
    file.write_all(bytes).map_err(io_error)?;
    file.flush().map_err(io_error)?;
    Ok(())
}

fn io_error(error: std::io::Error) -> BrokerError {
    let code = match error.raw_os_error() {
        #[cfg(unix)]
        Some(libc::ELOOP) => ErrorCode::UnsafePath,
        _ => ErrorCode::Io,
    };
    BrokerError::new(code, error.to_string())
}

fn open_audit(path: Option<&Path>) -> Option<File> {
    let path = path?;
    if let Some(parent) = path.parent() {
        if let Err(error) = std::fs::create_dir_all(parent) {
            eprintln!(
                "warning: sandbox audit directory {} is unavailable: {error}",
                parent.display()
            );
        }
    }
    match OpenOptions::new().create(true).append(true).open(path) {
        Ok(file) => Some(file),
        Err(error) => {
            eprintln!(
                "warning: sandbox audit log {} is unavailable: {error}",
                path.display()
            );
            None
        }
    }
}

fn log_audit(
    audit: &mut Option<File>,
    operation: &str,
    path: &str,
    ok: bool,
    error: Option<&str>,
    scope: Option<&str>,
) {
    let Some(file) = audit else {
        return;
    };
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let entry = serde_json::json!({
        "time": seconds,
        "op": operation,
        "path": path,
        "ok": ok,
        "error": error,
        "scope": scope,
    });
    if let Err(failure) = writeln!(file, "{entry}").and_then(|()| file.flush()) {
        eprintln!("warning: sandbox audit write failed: {failure}");
    }
}

#[cfg(unix)]
pub use client::{BrokerClient, Hello, WriteBroker};

#[cfg(unix)]
mod client {
    use std::io::{BufReader, Write};
    use std::path::Path;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;
    use std::time::Duration;

    use super::*;

    /// Default request timeout (see `docs/protocol.md` §7).
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

    /// Metadata returned by `hello`.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Hello {
        /// Backend name reported by the broker.
        pub sandbox: Option<String>,
        /// Profile name reported by the broker.
        pub profile: Option<String>,
    }

    struct ClientState {
        writer: std::os::unix::net::UnixStream,
        reader: BufReader<std::os::unix::net::UnixStream>,
    }

    /// Client used by the sandboxed agent to ask the broker for approved writes.
    pub struct BrokerClient {
        state: Mutex<ClientState>,
        next_id: AtomicU64,
    }

    impl BrokerClient {
        /// Connect to the broker socket with the default timeout.
        pub fn connect(path: &Path) -> Result<Self, BrokerError> {
            Self::connect_with_timeout(path, Some(DEFAULT_TIMEOUT))
        }

        /// Connect to the broker socket with an explicit timeout.
        pub fn connect_with_timeout(
            path: &Path,
            timeout: Option<Duration>,
        ) -> Result<Self, BrokerError> {
            let writer = std::os::unix::net::UnixStream::connect(path).map_err(client_io)?;
            if let Some(timeout) = timeout {
                writer.set_read_timeout(Some(timeout)).map_err(client_io)?;
                writer.set_write_timeout(Some(timeout)).map_err(client_io)?;
            }
            let reader = writer.try_clone().map_err(client_io)?;
            Ok(Self {
                state: Mutex::new(ClientState {
                    writer,
                    reader: BufReader::new(reader),
                }),
                next_id: AtomicU64::new(1),
            })
        }

        /// Handshake with the broker and validate the protocol version.
        pub fn hello(&self, client: &str, version: &str) -> Result<Hello, BrokerError> {
            let response = self.send(Operation::Hello {
                client: client.to_string(),
                version: version.to_string(),
            })?;
            Ok(Hello {
                sandbox: response.sandbox,
                profile: response.profile,
            })
        }

        /// Record an approval.
        pub fn approve(
            &self,
            path: &Path,
            operations: &[WriteOp],
            scope: ApprovalScope,
            recursive: bool,
        ) -> Result<(), BrokerError> {
            self.send(Operation::Approve {
                path: path.to_string_lossy().into_owned(),
                operations: operations.to_vec(),
                scope,
                recursive,
            })
            .map(|_| ())
        }

        /// Whether the broker already covers `path` for `operation`.
        pub fn is_approved(&self, path: &Path, operation: WriteOp) -> bool {
            self.check(path, operation).is_ok()
        }

        /// Validate an approval without consuming it.
        pub fn check(&self, path: &Path, operation: WriteOp) -> Result<(), BrokerError> {
            self.send(Operation::Check {
                path: path.to_string_lossy().into_owned(),
                operation,
            })
            .map(|_| ())
        }

        /// Revoke approvals at `path` (and below it when recursive).
        pub fn revoke(&self, path: &Path, recursive: bool) -> Result<(), BrokerError> {
            self.send(Operation::Revoke {
                path: path.to_string_lossy().into_owned(),
                recursive,
            })
            .map(|_| ())
        }

        /// Write bytes through the broker.
        pub fn write(&self, path: &Path, data: &[u8]) -> Result<(), BrokerError> {
            self.send(Operation::Write {
                path: path.to_string_lossy().into_owned(),
                data: base64::engine::general_purpose::STANDARD.encode(data),
                append: false,
            })
            .map(|_| ())
        }

        /// Append bytes through the broker.
        pub fn append(&self, path: &Path, data: &[u8]) -> Result<(), BrokerError> {
            self.send(Operation::Write {
                path: path.to_string_lossy().into_owned(),
                data: base64::engine::general_purpose::STANDARD.encode(data),
                append: true,
            })
            .map(|_| ())
        }

        /// Truncate a file through the broker.
        pub fn truncate(&self, path: &Path, len: u64) -> Result<(), BrokerError> {
            self.send(Operation::Truncate {
                path: path.to_string_lossy().into_owned(),
                len,
            })
            .map(|_| ())
        }

        /// Delete a file through the broker.
        pub fn delete(&self, path: &Path) -> Result<(), BrokerError> {
            self.send(Operation::Delete {
                path: path.to_string_lossy().into_owned(),
            })
            .map(|_| ())
        }

        /// Rename through the broker.
        pub fn rename(&self, path: &Path, target: &Path) -> Result<(), BrokerError> {
            self.send(Operation::Rename {
                path: path.to_string_lossy().into_owned(),
                target: target.to_string_lossy().into_owned(),
            })
            .map(|_| ())
        }

        /// Create a directory through the broker.
        pub fn mkdir(&self, path: &Path) -> Result<(), BrokerError> {
            self.send(Operation::Mkdir {
                path: path.to_string_lossy().into_owned(),
            })
            .map(|_| ())
        }

        fn send(&self, operation: Operation) -> Result<Response, BrokerError> {
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            let request = Request::new(id, operation);
            let mut state = self
                .state
                .lock()
                .map_err(|_| BrokerError::new(ErrorCode::Internal, "broker client poisoned"))?;
            let encoded = serde_json::to_string(&request)
                .map_err(|error| BrokerError::new(ErrorCode::Internal, error.to_string()))?;
            writeln!(state.writer, "{encoded}").map_err(client_io)?;
            state.writer.flush().map_err(client_io)?;

            let frame = read_frame(&mut state.reader, DEFAULT_MAX_PAYLOAD).map_err(client_io)?;
            let line = match frame {
                Frame::Eof => {
                    return Err(BrokerError::new(
                        ErrorCode::Io,
                        "broker closed the connection",
                    ))
                }
                Frame::TooLarge => {
                    return Err(BrokerError::new(
                        ErrorCode::TooLarge,
                        "broker reply exceeds the payload limit",
                    ))
                }
                Frame::Line(line) => line,
            };
            let response: Response = serde_json::from_str(&line).map_err(|error| {
                BrokerError::new(
                    ErrorCode::Internal,
                    format!("invalid broker reply: {error}"),
                )
            })?;
            if response.v != PROTOCOL_VERSION {
                return Err(BrokerError::new(
                    ErrorCode::Version,
                    format!(
                        "broker speaks protocol {}, expected {PROTOCOL_VERSION}",
                        response.v
                    ),
                ));
            }
            if response.id != id {
                return Err(BrokerError::new(
                    ErrorCode::Internal,
                    format!(
                        "broker reply id mismatch: expected {id}, got {}",
                        response.id
                    ),
                ));
            }
            if response.ok {
                Ok(response)
            } else {
                Err(BrokerError {
                    code: response.code.unwrap_or(ErrorCode::Internal),
                    message: response
                        .error
                        .unwrap_or_else(|| "broker refused the request".to_string()),
                })
            }
        }
    }

    fn client_io(error: std::io::Error) -> BrokerError {
        let code = match error.kind() {
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => ErrorCode::Timeout,
            _ => ErrorCode::Io,
        };
        BrokerError::new(code, error.to_string())
    }

    /// Operations the sandboxed agent can delegate to an unconfined broker.
    ///
    /// A trait rather than a concrete client so tool environments can be tested
    /// with a fake.
    pub trait WriteBroker: Send + Sync {
        /// Record an approval.
        fn approve(
            &self,
            path: &Path,
            operations: &[WriteOp],
            scope: ApprovalScope,
            recursive: bool,
        ) -> Result<(), BrokerError>;
        /// Drop approvals at a path (and its subtree when `recursive`).
        fn revoke(&self, path: &Path, recursive: bool) -> Result<(), BrokerError>;
        /// Whether an approval already covers `path` (no consumption).
        fn is_approved(&self, _path: &Path, _operation: WriteOp) -> bool {
            false
        }
        /// Write bytes.
        fn write(&self, path: &Path, data: &[u8]) -> Result<(), BrokerError>;
        /// Append bytes.
        fn append(&self, path: &Path, data: &[u8]) -> Result<(), BrokerError>;
        /// Truncate a file.
        fn truncate(&self, path: &Path, len: u64) -> Result<(), BrokerError>;
        /// Delete a file.
        fn delete(&self, path: &Path) -> Result<(), BrokerError>;
        /// Rename a file.
        fn rename(&self, path: &Path, target: &Path) -> Result<(), BrokerError>;
        /// Create a directory.
        fn mkdir(&self, path: &Path) -> Result<(), BrokerError>;
    }

    impl WriteBroker for BrokerClient {
        fn approve(
            &self,
            path: &Path,
            operations: &[WriteOp],
            scope: ApprovalScope,
            recursive: bool,
        ) -> Result<(), BrokerError> {
            BrokerClient::approve(self, path, operations, scope, recursive)
        }
        fn revoke(&self, path: &Path, recursive: bool) -> Result<(), BrokerError> {
            BrokerClient::revoke(self, path, recursive)
        }
        fn is_approved(&self, path: &Path, operation: WriteOp) -> bool {
            BrokerClient::is_approved(self, path, operation)
        }
        fn write(&self, path: &Path, data: &[u8]) -> Result<(), BrokerError> {
            BrokerClient::write(self, path, data)
        }
        fn append(&self, path: &Path, data: &[u8]) -> Result<(), BrokerError> {
            BrokerClient::append(self, path, data)
        }
        fn truncate(&self, path: &Path, len: u64) -> Result<(), BrokerError> {
            BrokerClient::truncate(self, path, len)
        }
        fn delete(&self, path: &Path) -> Result<(), BrokerError> {
            BrokerClient::delete(self, path)
        }
        fn rename(&self, path: &Path, target: &Path) -> Result<(), BrokerError> {
            BrokerClient::rename(self, path, target)
        }
        fn mkdir(&self, path: &Path) -> Result<(), BrokerError> {
            BrokerClient::mkdir(self, path)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::{ApprovalScope, WriteOp};
    use std::io::Cursor;

    fn run(requests: &[Request], audit: Option<PathBuf>) -> Vec<Response> {
        run_with_config(
            requests,
            BrokerConfig {
                audit,
                ..BrokerConfig::default()
            },
        )
    }

    fn run_with_config(requests: &[Request], config: BrokerConfig) -> Vec<Response> {
        let mut input = String::new();
        for request in requests {
            input.push_str(&serde_json::to_string(request).unwrap());
            input.push('\n');
        }
        let mut output = Vec::new();
        serve(Cursor::new(input), &mut output, config).unwrap();
        output
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).unwrap())
            .collect()
    }

    fn run_raw(input: &str, config: BrokerConfig) -> Vec<Response> {
        let mut output = Vec::new();
        serve(Cursor::new(input.as_bytes().to_vec()), &mut output, config).unwrap();
        output
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).unwrap())
            .collect()
    }

    fn approve(
        id: u64,
        path: &Path,
        operations: &[WriteOp],
        scope: ApprovalScope,
        recursive: bool,
    ) -> Request {
        Request::new(
            id,
            Operation::Approve {
                path: path.to_string_lossy().into_owned(),
                operations: operations.to_vec(),
                scope,
                recursive,
            },
        )
    }

    fn write(id: u64, path: &Path, data: &[u8], append: bool) -> Request {
        Request::new(
            id,
            Operation::Write {
                path: path.to_string_lossy().into_owned(),
                data: base64::engine::general_purpose::STANDARD.encode(data),
                append,
            },
        )
    }

    fn check(id: u64, path: &Path, operation: WriteOp) -> Request {
        Request::new(
            id,
            Operation::Check {
                path: path.to_string_lossy().into_owned(),
                operation,
            },
        )
    }

    fn revoke(id: u64, path: &Path, recursive: bool) -> Request {
        Request::new(
            id,
            Operation::Revoke {
                path: path.to_string_lossy().into_owned(),
                recursive,
            },
        )
    }

    #[test]
    fn hello_reports_backend_and_profile() {
        let responses = run_with_config(
            &[Request::new(
                1,
                Operation::Hello {
                    client: "rpi-sandbox-extension".to_string(),
                    version: "0.1.0".to_string(),
                },
            )],
            BrokerConfig {
                backend: Some("landlock".to_string()),
                profile: Some("default".to_string()),
                ..BrokerConfig::default()
            },
        );
        assert!(responses[0].ok);
        assert_eq!(responses[0].sandbox.as_deref(), Some("landlock"));
        assert_eq!(responses[0].profile.as_deref(), Some("default"));
        assert_eq!(responses[0].v, PROTOCOL_VERSION);
    }

    #[test]
    fn unapproved_write_is_rejected_without_touching_disk() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("a.txt");
        let responses = run(&[write(1, &target, b"x", false)], None);
        assert!(!responses[0].ok);
        assert_eq!(responses[0].code, Some(ErrorCode::NotApproved));
        assert!(!target.exists());
    }

    #[test]
    fn approved_write_creates_nested_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("nested/a.txt");
        let responses = run(
            &[
                approve(
                    1,
                    &target,
                    &[WriteOp::Create, WriteOp::Overwrite],
                    ApprovalScope::Session,
                    false,
                ),
                write(2, &target, b"approved", false),
            ],
            None,
        );
        assert!(responses[0].ok);
        assert!(responses[1].ok, "{:?}", responses[1]);
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "approved");
    }

    #[test]
    fn append_requires_append_approval() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("a.txt");
        std::fs::write(&target, b"start").unwrap();
        let responses = run(
            &[
                approve(
                    1,
                    &target,
                    &[WriteOp::Append],
                    ApprovalScope::Session,
                    false,
                ),
                write(2, &target, b"-more", true),
            ],
            None,
        );
        assert!(responses[1].ok, "{:?}", responses[1]);
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "start-more");
    }

    #[test]
    fn once_scope_is_consumed_by_a_write() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("once.txt");
        let responses = run(
            &[
                approve(
                    1,
                    &target,
                    &[WriteOp::Create, WriteOp::Overwrite],
                    ApprovalScope::Once,
                    false,
                ),
                write(2, &target, b"1", false),
                write(3, &target, b"2", false),
            ],
            None,
        );
        assert!(responses[1].ok);
        assert!(!responses[2].ok);
        assert_eq!(responses[2].code, Some(ErrorCode::NotApproved));
    }

    #[test]
    fn check_does_not_consume_once() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("checked.txt");
        let responses = run(
            &[
                approve(1, &target, &[WriteOp::Create], ApprovalScope::Once, false),
                check(2, &target, WriteOp::Create),
                check(3, &target, WriteOp::Create),
                write(4, &target, b"x", false),
                check(5, &target, WriteOp::Create),
            ],
            None,
        );
        assert!(responses[1].ok);
        assert!(responses[2].ok);
        assert!(responses[3].ok);
        assert!(!responses[4].ok);
    }

    #[test]
    fn relative_paths_are_rejected() {
        let responses = run(&[write(1, Path::new("relative.txt"), b"x", false)], None);
        assert_eq!(responses[0].code, Some(ErrorCode::InvalidPath));
    }

    #[test]
    fn paths_climbing_above_the_root_are_rejected() {
        let responses = run(&[write(1, Path::new("/../etc/passwd"), b"x", false)], None);
        assert_eq!(responses[0].code, Some(ErrorCode::InvalidPath));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_escape_is_reported_as_unsafe() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let allowed = dir.path().join("allowed");
        let outside = dir.path().join("outside");
        std::fs::create_dir(&allowed).unwrap();
        std::fs::create_dir(&outside).unwrap();
        symlink(&outside, allowed.join("escape")).unwrap();

        let responses = run(
            &[
                approve(
                    1,
                    &allowed,
                    &[WriteOp::Create, WriteOp::Overwrite],
                    ApprovalScope::Session,
                    true,
                ),
                write(2, &allowed.join("escape/leak.txt"), b"no", false),
            ],
            None,
        );
        assert_eq!(responses[1].code, Some(ErrorCode::UnsafePath));
        assert!(!outside.join("leak.txt").exists());
    }

    #[test]
    fn version_mismatch_is_rejected() {
        let responses = run_raw(
            r#"{"v":2,"id":9,"op":"hello","client":"x","version":"0.1.0"}"#,
            BrokerConfig::default(),
        );
        assert_eq!(responses[0].id, 9);
        assert_eq!(responses[0].code, Some(ErrorCode::Version));
    }

    #[test]
    fn unknown_operation_is_unsupported() {
        let responses = run_raw(
            r#"{"v":1,"id":3,"op":"teleport","path":"/tmp/x"}"#,
            BrokerConfig::default(),
        );
        assert_eq!(responses[0].code, Some(ErrorCode::Unsupported));
    }

    #[test]
    fn malformed_json_is_internal() {
        let responses = run_raw("not json\n", BrokerConfig::default());
        assert_eq!(responses[0].code, Some(ErrorCode::Internal));
        assert_eq!(responses[0].id, 0);
    }

    #[test]
    fn oversized_payload_is_rejected() {
        let config = BrokerConfig {
            max_payload: 64,
            ..BrokerConfig::default()
        };
        let responses = run_raw(
            &format!(
                "{{\"v\":1,\"id\":4,\"op\":\"hello\",\"client\":\"{}\",\"version\":\"1\"}}\n",
                "x".repeat(10_000)
            ),
            config,
        );
        assert_eq!(responses[0].code, Some(ErrorCode::TooLarge));
    }

    #[test]
    fn decoded_payload_limit_is_enforced() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("big.txt");
        let config = BrokerConfig {
            max_payload: 64,
            ..BrokerConfig::default()
        };
        let responses = run_with_config(
            &[
                approve(
                    1,
                    &target,
                    &[WriteOp::Create, WriteOp::Overwrite],
                    ApprovalScope::Session,
                    false,
                ),
                write(2, &target, &[b'x'; 100], false),
            ],
            config,
        );
        assert_eq!(responses[1].code, Some(ErrorCode::TooLarge));
        assert!(!target.exists());
    }

    #[test]
    fn audit_records_decisions_and_scopes() {
        let dir = tempfile::tempdir().unwrap();
        let audit = dir.path().join("audit.jsonl");
        let target = dir.path().join("audited.txt");
        run(
            &[
                approve(
                    1,
                    &target,
                    &[WriteOp::Create],
                    ApprovalScope::Session,
                    false,
                ),
                write(2, &target, b"x", false),
                revoke(3, &target, true),
                write(4, &target, b"y", false),
            ],
            Some(audit.clone()),
        );
        let text = std::fs::read_to_string(audit).unwrap();
        assert!(text.contains("\"op\":\"write\""));
        assert!(text.contains("\"scope\":\"session\""));
        assert!(text.contains("\"ok\":false"));
    }

    #[test]
    fn recursive_approval_covers_descendants() {
        let dir = tempfile::tempdir().unwrap();
        let child = dir.path().join("nested/deep/file.txt");
        let responses = run(
            &[
                approve(
                    1,
                    dir.path(),
                    &[WriteOp::Create, WriteOp::Overwrite],
                    ApprovalScope::Session,
                    true,
                ),
                write(2, &child, b"deep", false),
            ],
            None,
        );
        assert!(responses[1].ok, "{:?}", responses[1]);
        assert_eq!(std::fs::read_to_string(&child).unwrap(), "deep");
    }

    #[test]
    fn revoke_without_recursive_only_drops_the_exact_path() {
        let dir = tempfile::tempdir().unwrap();
        let one = dir.path().join("one.txt");
        let two = dir.path().join("two.txt");
        let responses = run(
            &[
                approve(
                    1,
                    &one,
                    &[WriteOp::Create, WriteOp::Overwrite],
                    ApprovalScope::Session,
                    false,
                ),
                approve(
                    2,
                    &two,
                    &[WriteOp::Create, WriteOp::Overwrite],
                    ApprovalScope::Session,
                    false,
                ),
                revoke(3, &one, false),
                write(4, &one, b"x", false),
                write(5, &two, b"y", false),
            ],
            None,
        );
        assert_eq!(responses[3].code, Some(ErrorCode::NotApproved));
        assert!(responses[4].ok);
    }

    #[test]
    fn recursive_revoke_drops_subtree_entries() {
        let dir = tempfile::tempdir().unwrap();
        let child = dir.path().join("child.txt");
        let responses = run(
            &[
                approve(
                    1,
                    &child,
                    &[WriteOp::Create, WriteOp::Overwrite],
                    ApprovalScope::Session,
                    false,
                ),
                revoke(2, dir.path(), true),
                write(3, &child, b"x", false),
            ],
            None,
        );
        assert_eq!(responses[2].code, Some(ErrorCode::NotApproved));
    }

    #[test]
    fn rename_requires_both_source_and_target_approvals() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.txt");
        let target = dir.path().join("target.txt");
        std::fs::write(&source, b"move").unwrap();
        let rename = |id| {
            Request::new(
                id,
                Operation::Rename {
                    path: source.to_string_lossy().into_owned(),
                    target: target.to_string_lossy().into_owned(),
                },
            )
        };
        let missing_target = run(
            &[
                approve(
                    1,
                    &source,
                    &[WriteOp::Rename],
                    ApprovalScope::Session,
                    false,
                ),
                rename(2),
            ],
            None,
        );
        assert_eq!(
            missing_target[1].code,
            Some(ErrorCode::NotApproved),
            "target create approval is required"
        );

        let both = run(
            &[
                approve(
                    1,
                    &source,
                    &[WriteOp::Rename],
                    ApprovalScope::Session,
                    false,
                ),
                approve(
                    2,
                    &target,
                    &[WriteOp::Create],
                    ApprovalScope::Session,
                    false,
                ),
                rename(3),
            ],
            None,
        );
        assert!(both[2].ok, "{:?}", both[2]);
        assert!(!source.exists());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "move");
    }

    #[test]
    fn delete_truncate_and_mkdir_are_approved_operations() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file.txt");
        std::fs::write(&file, b"0123456789").unwrap();
        let new_dir = dir.path().join("newdir");

        let responses = run(
            &[
                approve(
                    1,
                    &file,
                    &[WriteOp::Overwrite, WriteOp::Delete],
                    ApprovalScope::Session,
                    false,
                ),
                Request::new(
                    2,
                    Operation::Truncate {
                        path: file.to_string_lossy().into_owned(),
                        len: 3,
                    },
                ),
                approve(
                    3,
                    &new_dir,
                    &[WriteOp::Mkdir],
                    ApprovalScope::Session,
                    false,
                ),
                Request::new(
                    4,
                    Operation::Mkdir {
                        path: new_dir.to_string_lossy().into_owned(),
                    },
                ),
            ],
            None,
        );
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "012");
        assert!(new_dir.is_dir());
        assert!(responses[1].ok && responses[3].ok);

        let deleted = run(
            &[
                approve(1, &file, &[WriteOp::Delete], ApprovalScope::Session, false),
                Request::new(
                    2,
                    Operation::Delete {
                        path: file.to_string_lossy().into_owned(),
                    },
                ),
            ],
            None,
        );
        assert!(deleted[1].ok);
        assert!(!file.exists());
    }

    #[test]
    fn malformed_base64_is_internal() {
        let responses = run_raw(
            r#"{"v":1,"id":1,"op":"write","path":"/tmp/x","data":"***","append":false}"#,
            BrokerConfig::default(),
        );
        assert_eq!(responses[0].code, Some(ErrorCode::Internal));
    }

    #[test]
    fn approval_store_check_and_allow_agree() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f.txt");
        let mut store = ApprovalStore::default();
        store.approve(&file, &[WriteOp::Create], ApprovalScope::Session, false);
        assert_eq!(
            store.check(&file, WriteOp::Create),
            Some(ApprovalScope::Session)
        );
        assert_eq!(store.check(&file, WriteOp::Delete), None);
        assert_eq!(
            store.allow(&file, WriteOp::Create),
            Some(ApprovalScope::Session)
        );
        assert!(store.check(&file, WriteOp::Create).is_some());
    }

    #[test]
    fn empty_operations_are_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f.txt");
        let mut store = ApprovalStore::default();
        store.approve(&file, &[], ApprovalScope::Session, false);
        assert_eq!(store.check(&file, WriteOp::Create), None);
    }

    #[cfg(unix)]
    #[test]
    fn client_round_trip_over_a_unix_socket() {
        use std::os::unix::net::UnixListener;

        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("broker.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let reader = std::io::BufReader::new(stream.try_clone().unwrap());
            serve(
                reader,
                stream,
                BrokerConfig {
                    backend: Some("landlock".to_string()),
                    ..BrokerConfig::default()
                },
            )
            .unwrap();
        });

        let client = BrokerClient::connect(&socket_path).unwrap();
        let hello = client.hello("rpi-sandbox-extension", "0.1.0").unwrap();
        assert_eq!(hello.sandbox.as_deref(), Some("landlock"));

        let target = dir.path().join("client.txt");
        let error = client.write(&target, b"no").unwrap_err();
        assert_eq!(error.code, ErrorCode::NotApproved);

        client
            .approve(
                &target,
                &[WriteOp::Create, WriteOp::Overwrite],
                ApprovalScope::Session,
                false,
            )
            .unwrap();
        assert!(client.is_approved(&target, WriteOp::Create));
        client.write(&target, b"yes").unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "yes");
        client.revoke(&target, false).unwrap();
        assert!(!client.is_approved(&target, WriteOp::Create));

        drop(client);
        server.join().unwrap();
    }
}
