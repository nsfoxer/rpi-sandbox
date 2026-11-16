//! Minimal `bcrypt.dll` replacement for running `rpi.exe` under a restricted
//! token.
//!
//! # Why this exists
//!
//! Programs that statically import `bcrypt.dll` (for example `rustls`'s `ring`
//! backend, which calls `BCryptGenRandom`) fail to start inside a Windows
//! restricted token: the real `bcrypt.dll`'s `DllMain` returns `FALSE`, the
//! loader unloads it, and the process dies with
//! `STATUS_DLL_INIT_FAILED (0xC0000142)` before `main` runs. This is not an ACL
//! problem — ProcMon shows the image loading successfully with no access
//! denials, and no combination of token flags or extra group SIDs helps.
//!
//! # How it works
//!
//! Windows searches the application directory before `System32`, and
//! `bcrypt.dll` is not a KnownDLL, so a shim placed next to `rpi.exe` wins. The
//! shim has an inert `DllMain` (Rust's default for a `cdylib`) and implements
//! `BCryptGenRandom` on top of `RtlGenRandom` (`advapi32!SystemFunction036`),
//! which works inside the sandbox.
//!
//! # Limits
//!
//! Only `BCryptGenRandom` is exported. A binary that imports any other
//! `bcrypt.dll` symbol will fail to load. Replacing a system crypto DLL may
//! also trip antivirus heuristics. The proper fix is upstream: build rpi with
//! `rustls`' `aws-lc-rs` provider, which imports zero bcrypt symbols.

#[link(name = "advapi32")]
extern "system" {
    /// `SystemFunction036` — the documented-as-`RtlGenRandom` API.
    /// Returns `FALSE` (0) on failure.
    #[link_name = "SystemFunction036"]
    fn RtlGenRandom(buffer: *mut u8, length: u32) -> u8;
}

/// `NTSTATUS` success.
const STATUS_SUCCESS: i32 = 0;
/// `STATUS_INVALID_PARAMETER`.
const STATUS_INVALID_PARAMETER: i32 = 0xC000_000D_u32 as i32;
/// `STATUS_UNSUCCESSFUL`.
const STATUS_UNSUCCESSFUL: i32 = 0xC000_0001_u32 as i32;

/// `BCryptGenRandom(BCRYPT_ALG_HANDLE, PUCHAR, ULONG, ULONG) -> NTSTATUS`.
///
/// The algorithm handle and flags are ignored: every use we care about is
/// `BCRYPT_USE_SYSTEM_PREFERRED_RNG`, which is exactly what `RtlGenRandom`
/// provides.
#[no_mangle]
pub extern "system" fn BCryptGenRandom(
    _algorithm: *mut core::ffi::c_void,
    buffer: *mut u8,
    length: u32,
    _flags: u32,
) -> i32 {
    // A null buffer is the only argument error we can detect; length 0 is legal.
    if buffer.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    if unsafe { RtlGenRandom(buffer, length) } != 0 {
        STATUS_SUCCESS
    } else {
        STATUS_UNSUCCESSFUL
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fills_a_buffer() {
        let mut buffer = [0u8; 32];
        let status = BCryptGenRandom(
            std::ptr::null_mut(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            2,
        );
        assert_eq!(status, STATUS_SUCCESS);
        // 32 random bytes being all zero has probability 2^-256.
        assert!(
            buffer.iter().any(|&byte| byte != 0),
            "buffer was not filled"
        );
    }

    #[test]
    fn rejects_null_buffer() {
        let status = BCryptGenRandom(std::ptr::null_mut(), std::ptr::null_mut(), 16, 2);
        assert_eq!(status, STATUS_INVALID_PARAMETER);
    }

    #[test]
    fn zero_length_is_allowed() {
        let mut buffer = [0u8; 1];
        let status = BCryptGenRandom(std::ptr::null_mut(), buffer.as_mut_ptr(), 0, 2);
        assert_eq!(status, STATUS_SUCCESS);
    }
}
