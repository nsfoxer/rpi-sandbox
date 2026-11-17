//! Local IPC transport for the approval broker.
//!
//! The wire protocol ([`crate::protocol`]) is plain JSON Lines over a byte
//! stream, so the only platform-specific piece is how that stream is created:
//!
//! - Unix: a `0600` Unix domain socket in the temporary directory;
//! - Windows: a named pipe `\\.\pipe\rpi-sandbox-<pid>-<nonce>` whose DACL only
//!   grants the current user plus `ALL APPLICATION PACKAGES` for MXC.
//!
//! Everything above this module (broker, client, launcher supervision) is
//! platform-neutral and shared.

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Broker pipe/file buffer size on Windows, in bytes.
#[cfg(windows)]
const PIPE_BUFFER_SIZE: u32 = 64 * 1024;

/// A bound, not yet connected broker endpoint.
///
/// Unix listeners can accept repeatedly; a Windows listener transfers its
/// single pipe instance to the connection on the first [`Listener::accept`].
pub struct Listener {
    inner: imp::Listener,
}

impl Listener {
    /// Bind with the platform default security (current user only).
    pub fn bind() -> io::Result<Self> {
        Self::bind_with_sids(&[])
    }

    /// Bind with extra SIDs granted read/write access to the endpoint.
    ///
    /// On Unix the extra SIDs are ignored (the socket is `0600` and filesystem
    /// permissions apply). On Windows each entry must be a string SID such as
    /// `S-1-5-21-...`; the launcher passes the sandbox capability SIDs so the
    /// restricted child token can connect.
    pub fn bind_with_sids(extra_sids: &[String]) -> io::Result<Self> {
        Ok(Self {
            inner: imp::Listener::bind(extra_sids)?,
        })
    }

    /// Endpoint name: a socket path or a `\\.\pipe\...` name.
    pub fn name(&self) -> &Path {
        self.inner.name()
    }

    /// Block until a peer connects.
    pub fn accept(&self) -> io::Result<Conn> {
        Ok(Conn {
            inner: self.inner.accept()?,
        })
    }

    /// Block until the peer process matches `expected_pid`.
    ///
    /// The broker endpoint is reachable by any process inside the sandbox, so
    /// the first connection may come from a child or a malicious plugin. Drop
    /// mismatches and keep accepting instead of letting them occupy the single
    /// listener slot.
    pub fn accept_matching(&self, expected_pid: u32) -> io::Result<Conn> {
        Ok(Conn {
            inner: self.inner.accept_matching(expected_pid)?,
        })
    }

    /// Take the endpoint name without unlinking it.
    ///
    /// The Unix launcher uses this in the forked child: the broker parent keeps
    /// the bound path, the agent side only needs the name for the environment.
    pub fn into_name(self) -> PathBuf {
        self.inner.into_name()
    }
}

/// A connected broker stream.
pub struct Conn {
    inner: imp::Conn,
}

impl Conn {
    /// Connect to an endpoint created by [`Listener`].
    pub fn connect(name: &Path) -> io::Result<Self> {
        Ok(Self {
            inner: imp::Conn::connect(name)?,
        })
    }

    /// Duplicate the stream so one half can be wrapped in a `BufReader`.
    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            inner: self.inner.try_clone()?,
        })
    }

    /// Set the read timeout.
    ///
    /// Not supported for synchronous named pipes; on Windows this is a no-op
    /// and a broker that stops replying blocks the caller until it disconnects.
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.inner.set_read_timeout(timeout)
    }

    /// Set the write timeout (see [`Self::set_read_timeout`] for Windows).
    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.inner.set_write_timeout(timeout)
    }

    /// PID of the connected peer, when the platform can report it.
    pub fn peer_pid(&self) -> io::Result<u32> {
        self.inner.peer_pid()
    }
}

impl Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Write for Conn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(unix)]
mod imp {
    use std::fs::Permissions;
    use std::io::{self, Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    pub struct Listener {
        path: PathBuf,
        listener: UnixListener,
    }

    impl Listener {
        pub fn bind(_extra_sids: &[String]) -> io::Result<Self> {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.subsec_nanos())
                .unwrap_or(0);
            let path = std::env::temp_dir()
                .join(format!("rpi-sandbox-{}-{nonce}.sock", std::process::id()));
            // A stale socket from a crashed run must not block us.
            let _ = std::fs::remove_file(&path);
            let listener = UnixListener::bind(&path)?;
            std::fs::set_permissions(&path, Permissions::from_mode(0o600))?;
            Ok(Self { path, listener })
        }

        pub fn name(&self) -> &Path {
            &self.path
        }

        pub fn accept(&self) -> io::Result<Conn> {
            let (stream, _) = self.listener.accept()?;
            set_cloexec(&stream)?;
            Ok(Conn(stream))
        }

        pub fn accept_matching(&self, expected_pid: u32) -> io::Result<Conn> {
            loop {
                let conn = self.accept()?;
                match conn.peer_pid() {
                    Ok(pid) if pid == expected_pid => return Ok(conn),
                    Ok(_) => continue,
                    Err(error) => return Err(error),
                }
            }
        }

        pub fn into_name(mut self) -> PathBuf {
            std::mem::take(&mut self.path)
        }
    }

    impl Drop for Listener {
        fn drop(&mut self) {
            if !self.path.as_os_str().is_empty() {
                let _ = std::fs::remove_file(&self.path);
            }
        }
    }

    pub struct Conn(UnixStream);

    impl Conn {
        pub fn connect(name: &Path) -> io::Result<Self> {
            let stream = UnixStream::connect(name)?;
            set_cloexec(&stream)?;
            Ok(Self(stream))
        }

        pub fn try_clone(&self) -> io::Result<Self> {
            self.0.try_clone().map(Self)
        }

        pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
            self.0.set_read_timeout(timeout)
        }

        pub fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
            self.0.set_write_timeout(timeout)
        }

        /// PID of the process at the other end of the Unix socket.
        pub fn peer_pid(&self) -> io::Result<u32> {
            #[cfg(target_os = "linux")]
            {
                // SAFETY: `ucred` is plain old data; zeroing it is a valid
                // initial value for `getsockopt`.
                let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
                let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
                // SAFETY: the fd is valid for the lifetime of `self`, and both
                // out-pointers are valid for the duration of the call.
                let result = unsafe {
                    libc::getsockopt(
                        self.0.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_PEERCRED,
                        &mut credentials as *mut _ as *mut libc::c_void,
                        &mut length,
                    )
                };
                if result != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(credentials.pid as u32)
            }
            #[cfg(not(target_os = "linux"))]
            {
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "peer credentials are not available on this platform",
                ))
            }
        }
    }

    /// Keep the broker endpoint and accepted connections out of `exec`.
    fn set_cloexec(stream: &UnixStream) -> io::Result<()> {
        let fd = stream.as_raw_fd();
        // SAFETY: the fd is owned by `stream` and valid for both calls.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: same fd, valid flags from `F_GETFD`.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    impl Read for Conn {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.read(buf)
        }
    }

    impl Write for Conn {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.0.flush()
        }
    }
}

#[cfg(windows)]
mod imp {
    use std::cell::Cell;
    use std::io::{self, Read, Write};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, RawHandle};
    use std::path::{Path, PathBuf};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use windows_sys::Win32::Foundation::{
        CloseHandle, LocalFree, ERROR_PIPE_CONNECTED, HANDLE, HLOCAL, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    };
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenUser, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
        PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    use super::PIPE_BUFFER_SIZE;

    /// Owns a pipe instance until [`Listener::accept`] hands it to a [`Conn`].
    pub struct Listener {
        name: PathBuf,
        handle: Cell<HANDLE>,
    }

    // SAFETY: the listener only holds an owned kernel handle; handles have no
    // thread affinity and are closed exactly once from `Drop` or `accept`.
    unsafe impl Send for Listener {}

    impl Listener {
        pub fn bind(extra_sids: &[String]) -> io::Result<Self> {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_nanos() as u64)
                .unwrap_or(0);
            let name = format!(r"\\.\pipe\rpi-sandbox-{}-{nonce:x}", std::process::id());
            let sddl = pipe_sddl(extra_sids);
            let wide_sddl = wide(&sddl);

            let mut descriptor: *mut core::ffi::c_void = std::ptr::null_mut();
            // SAFETY: `wide_sddl` is NUL-terminated, revision 1 is the only
            // supported SDDL revision, and the returned descriptor is freed
            // below with `LocalFree` (the documented allocator).
            let ok = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    wide_sddl.as_ptr(),
                    1,
                    &mut descriptor,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            let attributes = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor,
                bInheritHandle: 0,
            };
            let wide_name = wide(&name);
            // SAFETY: the name and security descriptor are valid for the call;
            // the descriptor stays alive until CreateNamedPipeW has copied it.
            let handle = unsafe {
                CreateNamedPipeW(
                    wide_name.as_ptr(),
                    PIPE_ACCESS_DUPLEX,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                    1,
                    PIPE_BUFFER_SIZE,
                    PIPE_BUFFER_SIZE,
                    0,
                    &attributes,
                )
            };
            // SAFETY: the descriptor came from the conversion above.
            unsafe { LocalFree(descriptor as HLOCAL) };
            if handle == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }
            Ok(Self {
                name: PathBuf::from(name),
                handle: Cell::new(handle),
            })
        }

        pub fn name(&self) -> &Path {
            &self.name
        }

        pub fn accept(&self) -> io::Result<Conn> {
            let handle = self.handle.replace(std::ptr::null_mut());
            if handle.is_null() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "named pipe listener was already consumed",
                ));
            }
            // SAFETY: the handle is a valid pipe instance owned by us.
            let connected = unsafe { ConnectNamedPipe(handle, std::ptr::null_mut()) };
            if connected == 0 {
                let error = io::Error::last_os_error();
                // ERROR_PIPE_CONNECTED means a client won the race and is
                // already attached; that is success.
                if error.raw_os_error() != Some(ERROR_PIPE_CONNECTED as i32) {
                    // SAFETY: we still own the handle and must not leak it.
                    unsafe { CloseHandle(handle) };
                    return Err(error);
                }
            }
            // SAFETY: ownership of `handle` transfers to the `File`, which
            // closes it on drop.
            let file = unsafe { std::fs::File::from_raw_handle(handle as RawHandle) };
            Ok(Conn(file))
        }

        pub fn accept_matching(&self, expected_pid: u32) -> io::Result<Conn> {
            loop {
                let handle = self.handle.get();
                if handle.is_null() {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "named pipe listener was already consumed",
                    ));
                }
                // SAFETY: the handle is a valid pipe instance owned by us.
                let connected = unsafe { ConnectNamedPipe(handle, std::ptr::null_mut()) };
                if connected == 0 {
                    let error = io::Error::last_os_error();
                    if error.raw_os_error() != Some(ERROR_PIPE_CONNECTED as i32) {
                        self.handle.set(std::ptr::null_mut());
                        // SAFETY: we still own the handle.
                        unsafe { CloseHandle(handle) };
                        return Err(error);
                    }
                }
                let mut pid: u32 = 0;
                // SAFETY: the pipe is connected and `pid` is a valid out-pointer.
                let ok = unsafe { GetNamedPipeClientProcessId(handle, &mut pid) };
                if ok == 0 {
                    let error = io::Error::last_os_error();
                    // SAFETY: the handle is still owned by the listener; drop the
                    // connection before reporting the failure.
                    unsafe { DisconnectNamedPipe(handle) };
                    return Err(error);
                }
                if pid != expected_pid {
                    // The endpoint is reachable by any sandboxed process. Drop
                    // this client and keep the instance listening for the agent.
                    // SAFETY: the pipe is connected; the handle stays owned.
                    unsafe { DisconnectNamedPipe(handle) };
                    continue;
                }
                self.handle.set(std::ptr::null_mut());
                // SAFETY: ownership transfers to the `File`.
                let file = unsafe { std::fs::File::from_raw_handle(handle as RawHandle) };
                return Ok(Conn(file));
            }
        }

        pub fn into_name(self) -> PathBuf {
            self.name.clone()
        }
    }

    impl Drop for Listener {
        fn drop(&mut self) {
            let handle = self.handle.replace(std::ptr::null_mut());
            if !handle.is_null() {
                // SAFETY: the handle is owned by us and closed exactly once.
                unsafe { CloseHandle(handle) };
            }
        }
    }

    pub struct Conn(std::fs::File);

    impl Conn {
        pub fn connect(name: &Path) -> io::Result<Self> {
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(name)
                .map(Self)
        }

        pub fn try_clone(&self) -> io::Result<Self> {
            self.0.try_clone().map(Self)
        }

        pub fn set_read_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
            // Synchronous named pipes have no per-call timeout. Documented in
            // docs/protocol.md §7.
            Ok(())
        }

        pub fn set_write_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
            Ok(())
        }

        pub fn peer_pid(&self) -> io::Result<u32> {
            let mut pid: u32 = 0;
            // SAFETY: `self.0` owns a connected pipe handle, and `pid` is valid.
            let ok =
                unsafe { GetNamedPipeClientProcessId(self.0.as_raw_handle() as HANDLE, &mut pid) };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(pid)
        }
    }

    impl Read for Conn {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.read(buf)
        }
    }

    impl Write for Conn {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.0.flush()
        }
    }

    /// Build the pipe DACL: owner full control, plus read/write for every
    /// extra SID the launcher passes in.
    ///
    /// MXC workloads run in an AppContainer, which cannot open a pipe whose
    /// DACL only grants the interactive user; the launcher adds
    /// `ALL APPLICATION PACKAGES` (`S-1-15-2-1`).
    fn pipe_sddl(extra_sids: &[String]) -> String {
        let mut sddl = String::from("D:P");
        if let Some(user) = current_user_sid() {
            sddl.push_str(&format!("(A;;GA;;;{user})"));
        }
        for sid in extra_sids {
            sddl.push_str(&format!("(A;;GA;;;{sid})"));
        }
        sddl
    }

    /// String form of the current process token's user SID.
    fn current_user_sid() -> Option<String> {
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: the pseudo-handle is valid for the calling process and the
        // token handle is closed below.
        let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
        if ok == 0 {
            return None;
        }
        let mut needed: u32 = 0;
        // SAFETY: a NULL buffer with length 0 is the documented size query.
        unsafe {
            GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed);
        }
        let mut buffer = vec![0u8; needed as usize];
        // SAFETY: the buffer is at least `needed` bytes, as reported above.
        let ok = unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        };
        // SAFETY: the token handle is owned by us.
        unsafe { CloseHandle(token) };
        if ok == 0 {
            return None;
        }
        let user = unsafe { &*(buffer.as_ptr() as *const TOKEN_USER) };
        let mut text: *mut u16 = std::ptr::null_mut();
        // SAFETY: `user.User.Sid` points into `buffer` and is a valid SID.
        if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) } == 0 {
            return None;
        }
        let mut len = 0usize;
        // SAFETY: the API returned a NUL-terminated string.
        unsafe {
            while *text.add(len) != 0 {
                len += 1;
            }
        }
        let sid = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, len) });
        // SAFETY: the string was allocated by ConvertSidToStringSidW.
        unsafe { LocalFree(text as HLOCAL) };
        Some(sid)
    }

    fn wide(text: &str) -> Vec<u16> {
        std::ffi::OsStr::new(text)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::{serve, BrokerConfig};
    use crate::protocol::{read_frame, Frame, Operation, Request, Response};
    use std::io::{BufReader, Write};

    #[test]
    fn client_and_server_round_trip_over_the_native_transport() {
        let listener = Listener::bind().expect("bind");
        let name = listener.name().to_path_buf();
        let server = std::thread::spawn(move || {
            let conn = listener.accept().expect("accept");
            let reader = BufReader::new(conn.try_clone().expect("clone"));
            serve(reader, conn, BrokerConfig::default()).expect("serve");
        });

        let client = Conn::connect(&name).expect("connect");
        let mut writer = client.try_clone().expect("clone");
        let request = Request::new(
            1,
            Operation::Hello {
                client: "transport-test".to_string(),
                version: "0.1.0".to_string(),
            },
        );
        writeln!(writer, "{}", serde_json::to_string(&request).unwrap()).unwrap();
        writer.flush().unwrap();

        let mut reader = BufReader::new(client);
        let frame = read_frame(&mut reader, 4096).unwrap();
        match frame {
            Frame::Line(line) => {
                let response: Response = serde_json::from_str(&line).unwrap();
                assert!(response.ok);
            }
            other => panic!("unexpected frame: {other:?}"),
        }
        drop(reader);
        drop(writer);
        // The server ends when the client closes every handle.
        server.join().unwrap();
    }

    #[test]
    fn endpoint_names_are_stable_and_unique() {
        let first = Listener::bind().expect("bind");
        let second = Listener::bind().expect("bind");
        assert_ne!(first.name(), second.name());
        assert!(!first.name().as_os_str().is_empty());
    }

    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn peer_pid_reports_the_connected_process() {
        let listener = Listener::bind().expect("bind");
        let name = listener.name().to_path_buf();
        let server = std::thread::spawn(move || {
            let conn = listener.accept().expect("accept");
            conn.peer_pid().expect("peer pid")
        });
        let client = Conn::connect(&name).expect("connect");
        let pid = server.join().unwrap();
        assert_eq!(pid, std::process::id());
        drop(client);
    }
}
