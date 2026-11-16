//! Platform capability probing.
//!
//! Probing only reports what the kernel can enforce. It never applies a
//! sandbox. Reporting "supported" therefore does not mean the current process
//! is sandboxed; only the launcher can establish that boundary.

/// The mechanism a platform would use to enforce the filesystem policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SandboxBackend {
    /// Linux Landlock, with the detected ABI version.
    Landlock {
        /// Highest Landlock ABI version the kernel supports.
        abi: u32,
    },
    /// macOS Seatbelt (`sandbox_init`).
    Seatbelt,
    /// Windows restricted token with a synthetic SID.
    WindowsRestrictedToken,
    /// No confinement mechanism (explicit `--no-sandbox`).
    None,
}

impl SandboxBackend {
    /// Stable lowercase name used in diagnostics and status output.
    pub fn name(self) -> &'static str {
        match self {
            Self::Landlock { .. } => "landlock",
            Self::Seatbelt => "seatbelt",
            Self::WindowsRestrictedToken => "windows-restricted-token",
            Self::None => "none",
        }
    }
}

/// Result of probing the current platform.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SandboxSupport {
    /// The platform can enforce the policy.
    Supported(SandboxBackend),
    /// The platform cannot enforce the policy, with a human-readable reason.
    Unsupported {
        /// Why the backend is unavailable.
        reason: String,
    },
}

impl SandboxSupport {
    /// Whether a backend exists.
    pub fn is_supported(&self) -> bool {
        matches!(self, Self::Supported(_))
    }

    /// The available backend, if any.
    pub fn backend(&self) -> Option<SandboxBackend> {
        match self {
            Self::Supported(backend) => Some(*backend),
            Self::Unsupported { .. } => None,
        }
    }

    /// The reason the platform is unsupported, if it is.
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Supported(_) => None,
            Self::Unsupported { reason } => Some(reason),
        }
    }

    /// One-line diagnostic, for example `landlock (abi 6)`.
    pub fn describe(&self) -> String {
        match self {
            Self::Supported(SandboxBackend::Landlock { abi }) => {
                format!("landlock (abi {abi})")
            }
            Self::Supported(backend) => backend.name().to_string(),
            Self::Unsupported { reason } => format!("unavailable: {reason}"),
        }
    }
}

/// Probe the current platform without changing process state.
pub fn probe() -> SandboxSupport {
    #[cfg(target_os = "linux")]
    {
        return probe_linux();
    }
    #[cfg(target_os = "macos")]
    {
        return SandboxSupport::Unsupported {
            reason: "macOS Seatbelt backend is not implemented yet".to_string(),
        };
    }
    #[cfg(target_os = "windows")]
    {
        return probe_windows();
    }
    #[allow(unreachable_code)]
    SandboxSupport::Unsupported {
        reason: format!("unsupported platform: {}", std::env::consts::OS),
    }
}

#[cfg(target_os = "linux")]
fn probe_linux() -> SandboxSupport {
    match landlock_abi() {
        Ok(abi) => SandboxSupport::Supported(SandboxBackend::Landlock { abi }),
        Err(reason) => SandboxSupport::Unsupported { reason },
    }
}

/// `landlock_create_ruleset` with a null attribute and
/// `LANDLOCK_CREATE_RULESET_VERSION` returns the ABI version without installing
/// anything.
#[cfg(target_os = "linux")]
pub(crate) fn landlock_abi() -> Result<u32, String> {
    // Landlock tools use the generic syscall table; 444 is the same on
    // x86_64, aarch64, riscv, and others.
    const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
    const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;

    // SAFETY: `landlock_create_ruleset(2)` with a NULL attribute, zero size and
    // the VERSION flag is a read-only query: it installs no ruleset and touches
    // no user memory.
    let value = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            std::ptr::null::<libc::c_void>(),
            0_usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if value > 0 {
        return Ok(value as u32);
    }
    let error = std::io::Error::last_os_error();
    Err(match error.raw_os_error() {
        Some(libc::ENOSYS) => "kernel does not implement Landlock (needs Linux 5.13+)".to_string(),
        Some(libc::EOPNOTSUPP) => "Landlock is disabled in this kernel".to_string(),
        Some(libc::EPERM) => "Landlock is blocked by the current security policy".to_string(),
        _ => format!("Landlock probe failed: {error}"),
    })
}

/// Probe by building and discarding one restricted token.
///
/// `CreateRestrictedToken` is the only Windows API the backend cannot do
/// without; if it succeeds for the current user, ACL-based enforcement is
/// available. This touches no filesystem state.
#[cfg(target_os = "windows")]
fn probe_windows() -> SandboxSupport {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        CreateRestrictedToken, SID_AND_ATTRIBUTES, TOKEN_DUPLICATE, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    // Documented flag values (windows-sys does not define them).
    const DISABLE_MAX_PRIVILEGE: u32 = 0x01;
    const LUA_TOKEN: u32 = 0x04;
    const WRITE_RESTRICTED: u32 = 0x08;

    let mut base: HANDLE = std::ptr::null_mut();
    // SAFETY: the pseudo-handle is valid and the returned token is closed.
    let ok = unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_DUPLICATE | TOKEN_QUERY,
            &mut base,
        )
    };
    if ok == 0 {
        return SandboxSupport::Unsupported {
            reason: format!(
                "cannot open the process token: {}",
                std::io::Error::last_os_error()
            ),
        };
    }

    // `Everyone` (S-1-1-0) is only used to make the probe token realistically
    // restricted; it is never added to any ACL.
    let mut everyone: [u8; 12] = [0x01, 0x01, 0, 0, 0, 0, 0, 5, 0x01, 0, 0, 0];
    let entries = [SID_AND_ATTRIBUTES {
        Sid: everyone.as_mut_ptr() as windows_sys::Win32::Security::PSID,
        Attributes: 0,
    }];
    let mut restricted: HANDLE = std::ptr::null_mut();
    // SAFETY: `base` is a valid token, `entries` points at one valid SID, and
    // the new handle is closed below.
    let ok = unsafe {
        CreateRestrictedToken(
            base,
            DISABLE_MAX_PRIVILEGE | LUA_TOKEN | WRITE_RESTRICTED,
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
            entries.len() as u32,
            entries.as_ptr(),
            &mut restricted,
        )
    };
    // SAFETY: both handles are owned by this function.
    unsafe {
        CloseHandle(base);
        if !restricted.is_null() {
            CloseHandle(restricted);
        }
    }
    if ok == 0 {
        return SandboxSupport::Unsupported {
            reason: format!(
                "cannot create a restricted token: {}",
                std::io::Error::last_os_error()
            ),
        };
    }
    SandboxSupport::Supported(SandboxBackend::WindowsRestrictedToken)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_never_panics_and_has_a_description() {
        let support = probe();
        assert!(
            !support.describe().is_empty(),
            "probe must explain itself on every platform"
        );
        if let SandboxSupport::Unsupported { reason } = support {
            assert!(!reason.is_empty());
        }
    }

    #[test]
    fn backend_names_are_stable() {
        assert_eq!(SandboxBackend::Landlock { abi: 6 }.name(), "landlock");
        assert_eq!(SandboxBackend::Seatbelt.name(), "seatbelt");
        assert_eq!(
            SandboxBackend::WindowsRestrictedToken.name(),
            "windows-restricted-token"
        );
        assert_eq!(SandboxBackend::None.name(), "none");
    }

    #[cfg(windows)]
    #[test]
    fn windows_reports_the_restricted_token_backend() {
        assert_eq!(
            probe(),
            SandboxSupport::Supported(SandboxBackend::WindowsRestrictedToken)
        );
    }
}
