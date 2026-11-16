//! Windows backend: synthetic SID + ACLs + write-restricted token.
//!
//! # Why a launcher must spawn a child
//!
//! A restricted token is a process *primary* token; it cannot be applied to the
//! running process. The launcher therefore stays unconfined (and doubles as the
//! broker), spawns `rpi.exe` with `CreateProcessAsUserW`, waits for it, and
//! finally revokes the ACL entries it added.
//!
//! # Mechanism
//!
//! 1. derive two stable capability SIDs from `profile + cwd` (read and write);
//! 2. add `OI|CI` allow ACEs for the write SID on the writable roots, and deny
//!    ACEs for the write SID on protected paths;
//! 3. journal every ACE *before* adding it, so a crash is always recoverable;
//! 4. build a restricted token whose restricted SID list is
//!    `[write, read, logon, Everyone]` and whose restriction flags are
//!    `DISABLE_MAX_PRIVILEGE | LUA_TOKEN | WRITE_RESTRICTED`;
//! 5. give the token a default DACL that contains the logon SID, and enable
//!    `SeChangeNotifyPrivilege`;
//! 6. spawn the child with an explicit environment and a private desktop;
//! 7. serve approvals on a named pipe, wait, revoke, exit with the child's code.
//!
//! # Measured constraints (do not "simplify" these)
//!
//! - `DuplicateTokenEx` into a **primary** token is mandatory;
//!   `SetThreadToken` + `CreateProcessW` does not propagate to the child.
//! - restricted SID `Attributes` must be `0`; `SE_GROUP_ENABLED` makes
//!   `CreateRestrictedToken` fail with `ERROR_INVALID_PARAMETER (87)`.
//! - the base token needs `TOKEN_ADJUST_DEFAULT` and `TOKEN_ADJUST_PRIVILEGES`,
//!   otherwise `SetTokenInformation` / `AdjustTokenPrivileges` fail.
//! - without a default DACL containing the logon SID, DLL initialization dies
//!   with `STATUS_DLL_INIT_FAILED (0xC0000142)`.
//! - `SeChangeNotifyPrivilege` must be enabled or directory traversal breaks.
//! - `BUILTIN\Users` / `Authenticated Users` must **not** be in the restricted
//!   list: `WRITE_RESTRICTED` only gate-keeps writes, and adding them would
//!   widen the write surface to everything those groups can modify.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::Mutex;

use rpi_sandbox_core::backend::{BackendCapabilities, BackendPlan, LaunchSpec, SandboxBackend};
use rpi_sandbox_core::protocol::env;
use rpi_sandbox_core::state;
use rpi_sandbox_core::windows_plan::{self, AclPlan};
use rpi_sandbox_core::{
    AuditEvent, AuditLog, BrokerConfig, BrokerService, Listener, SandboxMode, SandboxPolicy,
    SandboxSupport,
};

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_SUCCESS, HANDLE, HLOCAL, WIN32_ERROR,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSidToSidW, GetNamedSecurityInfoW, SetEntriesInAclW,
    SetNamedSecurityInfoW, SetSecurityInfo, DENY_ACCESS, EXPLICIT_ACCESS_W, GRANT_ACCESS,
    SE_FILE_OBJECT, SE_WINDOW_OBJECT, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    AclSizeInformation, AddAce, AllocateAndInitializeSid, CreateRestrictedToken, DuplicateTokenEx,
    FreeSid, GetAce, GetAclInformation, GetLengthSid, GetTokenInformation, InitializeAcl,
    SetTokenInformation, TokenDefaultDacl, TokenGroups, TokenPrimary, ACL, ACL_SIZE_INFORMATION,
    DACL_SECURITY_INFORMATION, PSID, SECURITY_ATTRIBUTES, SECURITY_NT_AUTHORITY,
    SID_AND_ATTRIBUTES, TOKEN_ADJUST_DEFAULT, TOKEN_ADJUST_PRIVILEGES, TOKEN_ADJUST_SESSIONID,
    TOKEN_ALL_ACCESS, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_GROUPS, TOKEN_QUERY,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessAsUserW, GetCurrentProcess, GetExitCodeProcess, OpenProcess, OpenProcessToken,
    WaitForSingleObject, CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION, STARTF_USESTDHANDLES,
    STARTUPINFOW,
};

/// The single Windows backend instance.
pub static BACKEND: RestrictedTokenBackend = RestrictedTokenBackend;

/// `STATUS_DLL_INIT_FAILED`, the exit code seen when a statically imported
/// `bcrypt.dll` refuses to initialize under a restricted token.
const STATUS_DLL_INIT_FAILED: u32 = 0xC000_0142;

/// `CreateRestrictedToken` flags.
const DISABLE_MAX_PRIVILEGE: u32 = 0x01;
const LUA_TOKEN: u32 = 0x04;
/// Write access is checked against the restricted SID list.
const WRITE_RESTRICTED: u32 = 0x08;

/// `SE_GROUP_LOGON_ID` in `TOKEN_GROUPS.Attributes`.
const SE_GROUP_LOGON_ID: u32 = 0xC000_0000;

/// `SE_PRIVILEGE_ENABLED`.
const SE_PRIVILEGE_ENABLED: u32 = 0x0000_0002;

/// `ACL_REVISION`.
const ACL_REVISION: u32 = 2;

/// Append an ACE at the end of the list.
const ACE_INDEX_APPEND: u32 = 0xFFFF_FFFF;

/// `INHERITED_ACE` in `ACE_HEADER.AceFlags`.
const INHERITED_ACE: u8 = 0x10;

/// `INFINITE`.
const INFINITE: u32 = 0xFFFF_FFFF;

/// `PROCESS_QUERY_LIMITED_INFORMATION`.
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;

/// `STILL_ACTIVE`.
const STILL_ACTIVE: u32 = 259;

/// `GENERIC_ALL`, used for the logon SID in the token default DACL.
const GENERIC_ALL: u32 = 0x1000_0000;

/// `READ_CONTROL`, the only right granted to `OWNER RIGHTS` in the default DACL.
const READ_CONTROL: u32 = 0x0002_0000;

/// `DESKTOP_ALL_ACCESS`.
const DESKTOP_ALL_ACCESS: u32 = 0x000F_01FF;

/// Access requested when creating a private desktop: `DESKTOP_ALL_ACCESS` plus
/// `WRITE_DAC` and `READ_CONTROL`, which `SetSecurityInfo` needs.
const DESKTOP_CREATE_ACCESS: u32 = DESKTOP_ALL_ACCESS | 0x0004_0000 | 0x0002_0000;

/// Read+execute grant for read roots (specific bits, see `windows_plan`).
const READ_EXEC_ALLOW: u32 = windows_plan::READ_EXEC_ALLOW;

/// Console control events.
const CTRL_C_EVENT: u32 = 0;
const CTRL_BREAK_EVENT: u32 = 1;
const CTRL_CLOSE_EVENT: u32 = 2;
const CTRL_LOGOFF_EVENT: u32 = 5;
const CTRL_SHUTDOWN_EVENT: u32 = 6;

#[link(name = "kernel32")]
extern "system" {
    fn SetConsoleCtrlHandler(
        handler: Option<unsafe extern "system" fn(u32) -> i32>,
        add: i32,
    ) -> i32;
    fn GetStdHandle(which: u32) -> HANDLE;
}

#[link(name = "user32")]
extern "system" {
    fn CreateDesktopW(
        name: *const u16,
        device: *const u16,
        devmode: *const core::ffi::c_void,
        flags: u32,
        access: u32,
        attributes: *const SECURITY_ATTRIBUTES,
    ) -> HANDLE;
    fn CloseDesktop(desktop: HANDLE) -> i32;
}

/// `STD_INPUT_HANDLE` / `STD_OUTPUT_HANDLE` / `STD_ERROR_HANDLE`.
const STD_INPUT_HANDLE: u32 = 0xFFFF_FFF6u32; // (DWORD)-10
const STD_OUTPUT_HANDLE: u32 = 0xFFFF_FFF5u32; // (DWORD)-11
const STD_ERROR_HANDLE: u32 = 0xFFFF_FFF4u32; // (DWORD)-12

/// Windows launcher backend.
pub struct RestrictedTokenBackend;

impl SandboxBackend for RestrictedTokenBackend {
    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            name: "windows-restricted-token",
            // Deny ACEs can subtract a protected subtree from a writable root.
            can_subtract_protected: true,
            // ACL edits persist and must be rolled back.
            persistent_side_effects: true,
            needs_read_roots: true,
            missing_root_is_fatal: false,
        }
    }

    fn support(&self) -> SandboxSupport {
        rpi_sandbox_core::probe()
    }

    fn plan(&self, policy: &SandboxPolicy) -> Result<BackendPlan, String> {
        Ok(BackendPlan::Acl(windows_plan::build_plan(policy)))
    }

    fn launch(&self, plan: &BackendPlan, spec: LaunchSpec) -> Result<i32, String> {
        let BackendPlan::Acl(plan) = plan else {
            return Err("the Windows backend received a non-ACL plan".to_string());
        };
        let mut audit = AuditLog::open(spec.policy.audit_log.as_deref());

        // Everything that follows must be undone on both success and failure.
        let result = launch_inner(plan, &spec, &mut audit);
        cleanup_pending(&mut audit);
        result
    }
}

fn launch_inner(plan: &AclPlan, spec: &LaunchSpec, audit: &mut AuditLog) -> Result<i32, String> {
    // 1. A volume without persistent ACLs cannot enforce anything.
    for root in plan.paths() {
        match windows_plan::volume_supports_acls(&root) {
            Ok(true) => {}
            Ok(false) => {
                let message = format!(
                    "{} is on a volume without persistent ACLs (exFAT/FAT32/network share)",
                    root.display()
                );
                if spec.policy.mode == SandboxMode::Required {
                    return Err(format!("sandbox is required but {message}"));
                }
                eprintln!("warning: sandbox: {message}; enforcement is unreliable there");
            }
            Err(error) => eprintln!("warning: sandbox: {error}"),
        }
    }

    // 2. Recover ACLs left behind by a launcher that was killed, then open the
    //    journal for this run *before* the first ACE is written.
    sweep_journals(audit);
    begin_run()?;

    // 3. Capability SIDs are derived from the profile and the project directory
    //    so different projects never share a grant.
    let sids = CapabilitySids::derive(&spec.profile, &spec.cwd)?;

    // 4. Read roots: the target binary and its DLLs may be ACL'd to a specific
    //    user SID that the restricted side does not have. Failures are warnings:
    //    read access still works through the normal token SID.
    for root in &spec.read_roots {
        if !root.is_dir() {
            continue;
        }
        match set_ace(root, sids.read, READ_EXEC_ALLOW, false) {
            Ok(added) => {
                if added {
                    record(path_key(root), READ_EXEC_ALLOW, false, &sids.read_text);
                }
            }
            Err(error) => eprintln!("warning: sandbox: read root {}: {error}", root.display()),
        }
    }

    // 5. The real plan: allow writable roots, deny protected paths.
    for entry in &plan.allow {
        let added = set_ace(&entry.path, sids.write, entry.mask, false)
            .map_err(|error| format!("cannot grant write on {}: {error}", entry.path.display()))?;
        if added {
            record(path_key(&entry.path), entry.mask, false, &sids.write_text);
            audit.record(AuditEvent {
                op: "acl_allow",
                path: &path_key(&entry.path),
                ok: true,
                error: None,
                scope: None,
            });
        }
    }
    for entry in &plan.deny {
        let added = set_ace(&entry.path, sids.write, entry.mask, true)
            .map_err(|error| format!("cannot deny write on {}: {error}", entry.path.display()))?;
        if added {
            record(path_key(&entry.path), entry.mask, true, &sids.write_text);
            audit.record(AuditEvent {
                op: "acl_deny",
                path: &path_key(&entry.path),
                ok: true,
                error: None,
                scope: None,
            });
        }
    }

    // 6. Broker endpoint, bound before the child starts so the extension can
    //    connect during library initialization.
    let mut child_env = spec.env.clone();
    let mut broker_config = None;
    let mut listener = None;
    if let Some(config) = spec.broker.clone() {
        let bound = Listener::bind_with_sids(&[sids.read_text.clone(), sids.write_text.clone()])
            .map_err(|error| format!("cannot create the broker pipe: {error}"))?;
        child_env.set(env::SOCKET, bound.name().as_os_str());
        broker_config = Some(config);
        listener = Some(bound);
    }
    if let Some(listener) = listener {
        start_broker(listener, broker_config.expect("broker config"));
    }

    // 7. Restricted primary token.
    let token = build_token(sids.write, sids.read)?;

    // 8. Spawn under the token, wait, and translate the exit code.
    let environment = environment_block(&child_env);
    let code = spawn_child(&token, spec, &environment)?;
    if code == STATUS_DLL_INIT_FAILED {
        eprintln!(
            "rpi-sandbox: rpi.exe exited with STATUS_DLL_INIT_FAILED (0xC0000142).\n\
             This is the bcrypt.dll incompatibility: the real bcrypt.dll refuses to \
             initialize under a restricted token.\n\
             Fix: put the bcrypt.dll produced by `bcrypt-shim/` next to rpi.exe \
             (e.g. sandbox\\bin\\rpi.exe + sandbox\\bin\\bcrypt.dll), or rebuild rpi \
             with rustls' aws-lc-rs provider (no bcrypt import)."
        );
    }
    Ok(code as i32)
}

// ---------------------------------------------------------------------------
// Capability SIDs
// ---------------------------------------------------------------------------

/// The two synthetic SIDs a sandbox grants.
struct CapabilitySids {
    read: PSID,
    write: PSID,
    read_text: String,
    write_text: String,
}

impl CapabilitySids {
    fn derive(profile: &str, cwd: &Path) -> Result<Self, String> {
        let seed = seed_from(profile, cwd);
        let read = synthetic_sid(seed)
            .ok_or_else(|| "cannot allocate the read capability SID".to_string())?;
        let write = synthetic_sid(seed ^ 0x9E37_79B9_7F4A_7C15)
            .ok_or_else(|| "cannot allocate the write capability SID".to_string())?;
        let read_text = sid_to_string(read)
            .ok_or_else(|| "cannot stringify the read capability SID".to_string())?;
        let write_text = sid_to_string(write)
            .ok_or_else(|| "cannot stringify the write capability SID".to_string())?;
        Ok(Self {
            read,
            write,
            read_text,
            write_text,
        })
    }
}

impl Drop for CapabilitySids {
    fn drop(&mut self) {
        // SAFETY: both SIDs were allocated by `AllocateAndInitializeSid` and are
        // freed exactly once.
        unsafe {
            FreeSid(self.read);
            FreeSid(self.write);
        }
    }
}

/// FNV-1a over `profile`, a NUL separator, and the canonical working directory.
fn seed_from(profile: &str, cwd: &Path) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let canonical = rpi_sandbox_core::normalize_and_resolve(cwd);
    for byte in profile
        .as_bytes()
        .iter()
        .copied()
        .chain(std::iter::once(0).chain(canonical.to_string_lossy().as_bytes().iter().copied()))
    {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Stable synthetic SID `S-1-5-21-<a>-<b>-<c>-<d>`.
fn synthetic_sid(seed: u64) -> Option<PSID> {
    let a = ((seed >> 48) & 0x7FFF) as u32;
    let b = ((seed >> 32) & 0xFFFF) as u32;
    let c = ((seed >> 16) & 0xFFFF) as u32;
    let d = (seed & 0xFFFF) as u32;
    let mut sid: PSID = ptr::null_mut();
    // SAFETY: `SECURITY_NT_AUTHORITY` is a valid identifier authority and the
    // out pointer is written only on success.
    let ok = unsafe {
        AllocateAndInitializeSid(&SECURITY_NT_AUTHORITY, 5, 21, a, b, c, d, 0, 0, 0, &mut sid)
    };
    (ok != 0).then_some(sid)
}

fn sid_to_string(sid: PSID) -> Option<String> {
    let mut text: *mut u16 = ptr::null_mut();
    // SAFETY: `sid` is a valid SID; the returned string is freed below.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return None;
    }
    let mut len = 0usize;
    // SAFETY: the API returned a NUL-terminated string.
    unsafe {
        while *text.add(len) != 0 {
            len += 1;
        }
    }
    let value = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, len) });
    // SAFETY: allocated by `ConvertSidToStringSidW`.
    unsafe { LocalFree(text as HLOCAL) };
    Some(value)
}

fn sid_from_string(text: &str) -> Result<PSID, String> {
    let wide = wide(text);
    let mut sid: PSID = ptr::null_mut();
    // SAFETY: `wide` is NUL-terminated; the SID is freed by the caller.
    if unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut sid) } == 0 {
        return Err(format!(
            "invalid SID {text}: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(sid)
}

// ---------------------------------------------------------------------------
// ACL editing
// ---------------------------------------------------------------------------

/// Add `mask` for `sid` on `path`, unless an identical ACE is already present.
///
/// Returns whether an ACE was added. Idempotency matters: without it every run
/// appends another ACE and the DACL grows without bound.
fn set_ace(path: &Path, sid: PSID, mask: u32, deny: bool) -> Result<bool, String> {
    let wide_path = wide(path.as_os_str());
    let mut old_dacl: *mut ACL = ptr::null_mut();
    let mut descriptor: *mut core::ffi::c_void = ptr::null_mut();
    // SAFETY: the path is NUL-terminated and the out pointers are valid.
    let code = unsafe {
        GetNamedSecurityInfoW(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut old_dacl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if code != ERROR_SUCCESS {
        return Err(format!("GetNamedSecurityInfo failed: {}", error_text(code)));
    }

    if ace_present(old_dacl, sid, mask, deny) {
        // SAFETY: the descriptor was allocated by GetNamedSecurityInfo.
        unsafe { LocalFree(descriptor as HLOCAL) };
        return Ok(false);
    }

    let entry = EXPLICIT_ACCESS_W {
        grfAccessPermissions: mask,
        grfAccessMode: if deny { DENY_ACCESS } else { GRANT_ACCESS },
        grfInheritance: windows_sys::Win32::Security::OBJECT_INHERIT_ACE
            | windows_sys::Win32::Security::CONTAINER_INHERIT_ACE,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: ptr::null_mut(),
            MultipleTrusteeOperation: 0,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_UNKNOWN,
            ptstrName: sid as *mut u16,
        },
    };
    let mut new_dacl: *mut ACL = ptr::null_mut();
    // SAFETY: one valid entry; `old_dacl` may be NULL (no DACL).
    let code = unsafe { SetEntriesInAclW(1, &entry, old_dacl, &mut new_dacl) };
    if code != ERROR_SUCCESS {
        // SAFETY: descriptor is owned here.
        unsafe { LocalFree(descriptor as HLOCAL) };
        return Err(format!("SetEntriesInAcl failed: {}", error_text(code)));
    }

    // SAFETY: `new_dacl` is a valid ACL from the call above.
    let code = unsafe {
        SetNamedSecurityInfoW(
            wide_path.as_ptr() as *mut u16,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            new_dacl,
            ptr::null_mut(),
        )
    };
    // SAFETY: both allocations are owned here.
    unsafe {
        LocalFree(new_dacl as HLOCAL);
        LocalFree(descriptor as HLOCAL);
    }
    if code != ERROR_SUCCESS {
        return Err(format!("SetNamedSecurityInfo failed: {}", error_text(code)));
    }
    Ok(true)
}

/// Remove the ACE that exactly matches `(sid, mask, deny)` from `path`.
///
/// The DACL is rebuilt by copying every other ACE **verbatim** (including
/// object ACEs) so ordering and semantics are preserved. `SetEntriesInAclW`
/// cannot delete entries, and rebuilding from parsed fields would drop ACE
/// types it does not model.
fn revoke_ace(path: &Path, sid: PSID, mask: u32, deny: bool) -> Result<(), String> {
    let wide_path = wide(path.as_os_str());
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut descriptor: *mut core::ffi::c_void = ptr::null_mut();
    // SAFETY: the path is NUL-terminated and the out pointers are valid.
    let code = unsafe {
        GetNamedSecurityInfoW(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if code != ERROR_SUCCESS {
        return Err(format!("GetNamedSecurityInfo failed: {}", error_text(code)));
    }
    if dacl.is_null() {
        // SAFETY: descriptor is owned here.
        unsafe { LocalFree(descriptor as HLOCAL) };
        return Ok(());
    }

    let mut info: ACL_SIZE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: `dacl` is a valid ACL and `info` is the right size.
    let ok = unsafe {
        GetAclInformation(
            dacl,
            &mut info as *mut _ as *mut core::ffi::c_void,
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    };
    if ok == 0 {
        // SAFETY: descriptor is owned here.
        unsafe { LocalFree(descriptor as HLOCAL) };
        return Err("GetAclInformation failed".to_string());
    }

    let mut kept: Vec<(*const u8, u32)> = Vec::new();
    for index in 0..info.AceCount {
        let mut ace: *mut core::ffi::c_void = ptr::null_mut();
        // SAFETY: `index` is within `AceCount`.
        if unsafe { GetAce(dacl, index, &mut ace) } == 0 {
            continue;
        }
        let bytes = ace as *const u8;
        // SAFETY: every ACE starts with the 4-byte header; AceSize sits at 2.
        let size = unsafe { u16::from_le_bytes([*bytes.add(2), *bytes.add(3)]) } as u32;
        if size < 8 {
            continue;
        }
        // SAFETY: the header and mask are within the ACE.
        let ace_type = unsafe { *bytes };
        let ace_mask = unsafe {
            u32::from_le_bytes([*bytes.add(4), *bytes.add(5), *bytes.add(6), *bytes.add(7)])
        };
        // SAFETY: the SID starts right after the mask.
        let ace_sid = unsafe { bytes.add(8) as PSID };
        // SAFETY: the flags byte is inside the ACE header.
        let ace_flags = unsafe { *bytes.add(1) };
        // Inherited ACEs are re-propagated by the object manager when the DACL
        // is set; copying them would turn them into explicit entries.
        if ace_flags & INHERITED_ACE != 0 {
            continue;
        }
        let is_deny = ace_type == 1;
        let matches = unsafe { windows_sys::Win32::Security::EqualSid(ace_sid, sid) } != 0
            && ace_mask == mask
            && is_deny == deny;
        if matches {
            continue;
        }
        kept.push((bytes, size));
    }

    let total = std::mem::size_of::<ACL>() as u32 + kept.iter().map(|(_, size)| *size).sum::<u32>();
    // `Vec<u32>` keeps the buffer DWORD-aligned, which ACLs require.
    let mut buffer = vec![0u32; (total as usize).div_ceil(4)];
    let new_dacl = buffer.as_mut_ptr() as *mut ACL;
    // SAFETY: the buffer is large enough for the header plus kept ACEs.
    if unsafe { InitializeAcl(new_dacl, total, ACL_REVISION) } == 0 {
        // SAFETY: descriptor is owned here.
        unsafe { LocalFree(descriptor as HLOCAL) };
        return Err("InitializeAcl failed".to_string());
    }
    for (bytes, size) in &kept {
        // SAFETY: each ACE was copied from a valid DACL and fits in `buffer`.
        if unsafe {
            AddAce(
                new_dacl,
                ACL_REVISION,
                ACE_INDEX_APPEND,
                *bytes as *const core::ffi::c_void,
                *size,
            )
        } == 0
        {
            // SAFETY: descriptor is owned here.
            unsafe { LocalFree(descriptor as HLOCAL) };
            return Err("AddAce failed".to_string());
        }
    }

    // SAFETY: `new_dacl` is a complete ACL and stays alive for the call.
    let code = unsafe {
        SetNamedSecurityInfoW(
            wide_path.as_ptr() as *mut u16,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            new_dacl,
            ptr::null_mut(),
        )
    };
    // SAFETY: descriptor is owned here; `buffer` is dropped normally.
    unsafe { LocalFree(descriptor as HLOCAL) };
    if code != ERROR_SUCCESS {
        return Err(format!("SetNamedSecurityInfo failed: {}", error_text(code)));
    }
    Ok(())
}

/// Whether `dacl` already contains a matching allow/deny ACE for `sid`.
fn ace_present(dacl: *const ACL, sid: PSID, mask: u32, deny: bool) -> bool {
    if dacl.is_null() {
        return false;
    }
    let mut info: ACL_SIZE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: `dacl` is a valid ACL and `info` is the right size.
    let ok = unsafe {
        GetAclInformation(
            dacl,
            &mut info as *mut _ as *mut core::ffi::c_void,
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    };
    if ok == 0 {
        return false;
    }
    for index in 0..info.AceCount {
        let mut ace: *mut core::ffi::c_void = ptr::null_mut();
        // SAFETY: `index` is within `AceCount`.
        if unsafe { GetAce(dacl, index, &mut ace) } == 0 {
            continue;
        }
        let bytes = ace as *const u8;
        // SAFETY: the header and mask are inside every well-formed ACE.
        let ace_type = unsafe { *bytes };
        let ace_mask = unsafe {
            u32::from_le_bytes([*bytes.add(4), *bytes.add(5), *bytes.add(6), *bytes.add(7)])
        };
        // SAFETY: the SID starts right after the mask.
        let ace_sid = unsafe { bytes.add(8) as PSID };
        let is_deny = ace_type == 1;
        if ace_mask == mask
            && is_deny == deny
            && unsafe { windows_sys::Win32::Security::EqualSid(ace_sid, sid) } != 0
        {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Journal
// ---------------------------------------------------------------------------

/// One ACE this launcher added.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct JournalEntry {
    path: String,
    mask: u32,
    deny: bool,
    sid: String,
}

/// On-disk record of a run's ACL edits.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct Journal {
    /// `<pid>-<nonce>`; also the file stem.
    id: String,
    pid: u32,
    created: u64,
    entries: Vec<JournalEntry>,
}

/// State replayed when the process exits or receives a console close event.
struct Pending {
    journal: PathBuf,
    entries: Vec<JournalEntry>,
}

static PENDING: Mutex<Option<Pending>> = Mutex::new(None);

fn journal_path(id: &str) -> PathBuf {
    state::acl_journal_dir().join(format!("{id}.json"))
}

fn record(path: String, mask: u32, deny: bool, sid: &str) {
    let entry = JournalEntry {
        path,
        mask,
        deny,
        sid: sid.to_string(),
    };
    let mut pending = PENDING.lock().unwrap_or_else(|error| error.into_inner());
    let Some(state) = pending.as_mut() else {
        return;
    };
    state.entries.push(entry);
    if let Err(error) = save_journal(&state.journal, &state.entries) {
        eprintln!("warning: sandbox: cannot update the ACL journal: {error}");
    }
}

/// Write the journal before the matching ACE is applied.
fn save_journal(path: &Path, entries: &[JournalEntry]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
    }
    let id = path
        .file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .unwrap_or_default();
    let journal = Journal {
        id,
        pid: std::process::id(),
        created: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0),
        entries: entries.to_vec(),
    };
    let text = serde_json::to_string(&journal)
        .map_err(|error| format!("cannot serialize the journal: {error}"))?;
    let mut file = std::fs::File::create(path)
        .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
    use std::io::Write;
    file.write_all(text.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("cannot flush {}: {error}", path.display()))
}

/// Start a journal for this run. Must happen before the first ACE is added.
fn begin_journal() -> Result<(), String> {
    let id = format!("{}-{:x}", std::process::id(), state::nonce());
    let path = journal_path(&id);
    let mut pending = PENDING.lock().unwrap_or_else(|error| error.into_inner());
    *pending = Some(Pending {
        journal: path.clone(),
        entries: Vec::new(),
    });
    save_journal(&path, &[])
}

/// Revoke everything recorded by this run and delete the journal.
fn cleanup_pending(audit: &mut AuditLog) {
    let mut pending = PENDING.lock().unwrap_or_else(|error| error.into_inner());
    let Some(state) = pending.take() else {
        return;
    };
    for entry in &state.entries {
        if let Err(error) = revoke_entry(entry) {
            eprintln!(
                "warning: sandbox: cannot revoke the ACE on {}: {error}",
                entry.path
            );
            continue;
        }
        audit.record(AuditEvent {
            op: "acl_revoke",
            path: &entry.path,
            ok: true,
            error: None,
            scope: None,
        });
    }
    let _ = std::fs::remove_file(&state.journal);
}

fn revoke_entry(entry: &JournalEntry) -> Result<(), String> {
    let sid = sid_from_string(&entry.sid)?;
    // SAFETY: the SID is freed right after the call.
    let result = revoke_ace(Path::new(&entry.path), sid, entry.mask, entry.deny);
    // SAFETY: allocated by `ConvertStringSidToSidW`.
    unsafe { LocalFree(sid as HLOCAL) };
    result
}

/// Replay journals whose owner process is gone.
fn sweep_journals(audit: &mut AuditLog) {
    let dir = state::acl_journal_dir();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().map(|ext| ext != "json").unwrap_or(true) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(journal) = serde_json::from_str::<Journal>(&text) else {
            let _ = std::fs::remove_file(&path);
            continue;
        };
        if process_alive(journal.pid) {
            continue;
        }
        for record in &journal.entries {
            if let Err(error) = revoke_entry(record) {
                eprintln!(
                    "warning: sandbox: cannot recover the ACE on {}: {error}",
                    record.path
                );
            }
        }
        audit.record(AuditEvent {
            op: "journal_replay",
            path: &path_key(&path),
            ok: true,
            error: None,
            scope: None,
        });
        let _ = std::fs::remove_file(&path);
    }
}

fn process_alive(pid: u32) -> bool {
    // SAFETY: the returned handle is closed below.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return false;
    }
    let mut code: u32 = 0;
    // SAFETY: the handle has PROCESS_QUERY_LIMITED_INFORMATION.
    let ok = unsafe { GetExitCodeProcess(handle, &mut code) };
    // SAFETY: the handle is owned here.
    unsafe { CloseHandle(handle) };
    ok != 0 && code == STILL_ACTIVE
}

// ---------------------------------------------------------------------------
// Token
// ---------------------------------------------------------------------------

/// Owns the primary token handed to `CreateProcessAsUserW`.
struct PrimaryToken(HANDLE);

impl Drop for PrimaryToken {
    fn drop(&mut self) {
        // SAFETY: the handle is owned by this wrapper.
        unsafe { CloseHandle(self.0) };
    }
}

fn build_token(write: PSID, read: PSID) -> Result<PrimaryToken, String> {
    let mut base: HANDLE = ptr::null_mut();
    let access = TOKEN_DUPLICATE
        | TOKEN_QUERY
        | TOKEN_ASSIGN_PRIMARY
        | TOKEN_ADJUST_DEFAULT
        | TOKEN_ADJUST_SESSIONID
        | TOKEN_ADJUST_PRIVILEGES;
    // SAFETY: the pseudo-handle is valid and the token is closed below.
    if unsafe { OpenProcessToken(GetCurrentProcess(), access, &mut base) } == 0 {
        return Err(format!(
            "cannot open the process token: {}",
            std::io::Error::last_os_error()
        ));
    }

    let logon = logon_sid(base);
    let mut buffers: Vec<Vec<u8>> = Vec::new();
    if let Some(logon) = &logon {
        buffers.push(logon.clone());
    } else {
        eprintln!("warning: sandbox: no logon SID; session objects may be inaccessible");
    }
    // Everyone (S-1-1-0) is required so the restricted check still lets the
    // child read world-readable locations.
    buffers.push(everyone_bytes());

    let mut entries: Vec<SID_AND_ATTRIBUTES> = vec![
        SID_AND_ATTRIBUTES {
            Sid: write,
            Attributes: 0,
        },
        SID_AND_ATTRIBUTES {
            Sid: read,
            Attributes: 0,
        },
    ];
    for buffer in buffers.iter_mut() {
        entries.push(SID_AND_ATTRIBUTES {
            Sid: buffer.as_mut_ptr() as PSID,
            Attributes: 0,
        });
    }

    let mut restricted: HANDLE = ptr::null_mut();
    // SAFETY: the base token is valid, every SID in `entries` outlives the
    // call, and the new handle is owned here.
    let ok = unsafe {
        CreateRestrictedToken(
            base,
            DISABLE_MAX_PRIVILEGE | LUA_TOKEN | WRITE_RESTRICTED,
            0,
            ptr::null(),
            0,
            ptr::null(),
            entries.len() as u32,
            entries.as_ptr(),
            &mut restricted,
        )
    };
    // SAFETY: the base token is owned here.
    unsafe { CloseHandle(base) };
    if ok == 0 {
        return Err(format!(
            "cannot create a restricted token: {}",
            std::io::Error::last_os_error()
        ));
    }

    // A default DACL containing the logon SID is required for DLL
    // initialization; a failure here is usually fatal at startup, so warn with
    // the concrete reason.
    if let Some(logon) = logon.as_deref() {
        let logon_sid = logon.as_ptr() as PSID;
        if let Err(error) = set_default_dacl(restricted, logon_sid) {
            eprintln!("warning: sandbox: {error}; DLL initialization may fail");
        }
    }
    if let Err(error) = enable_single_privilege(restricted, "SeChangeNotifyPrivilege") {
        eprintln!(
            "warning: sandbox: {error};
             "
        );
    }

    let mut primary: HANDLE = ptr::null_mut();
    // SAFETY: `restricted` is a valid token; `SecurityImpersonation` (2) and
    // `TokenPrimary` (1) are the documented constants.
    let ok = unsafe {
        DuplicateTokenEx(
            restricted,
            TOKEN_ALL_ACCESS,
            ptr::null(),
            2,
            TokenPrimary,
            &mut primary,
        )
    };
    // SAFETY: the restricted token is owned here.
    unsafe { CloseHandle(restricted) };
    if ok == 0 {
        return Err(format!(
            "cannot duplicate the restricted token: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(PrimaryToken(primary))
}

/// Copy of the logon SID from `token`'s group list.
fn logon_sid(token: HANDLE) -> Option<Vec<u8>> {
    let mut needed: u32 = 0;
    // SAFETY: NULL with length 0 is the documented size query.
    unsafe { GetTokenInformation(token, TokenGroups, ptr::null_mut(), 0, &mut needed) };
    if needed == 0 {
        return None;
    }
    let mut buffer = vec![0u8; needed as usize];
    // SAFETY: the buffer is at least `needed` bytes.
    if unsafe {
        GetTokenInformation(
            token,
            TokenGroups,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return None;
    }
    // SAFETY: the buffer holds a TOKEN_GROUPS followed by its entries.
    let groups = unsafe { &*(buffer.as_ptr() as *const TOKEN_GROUPS) };
    // SAFETY: `GroupCount` entries are present in the buffer.
    let entries =
        unsafe { std::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize) };
    for entry in entries {
        if entry.Attributes & SE_GROUP_LOGON_ID == SE_GROUP_LOGON_ID {
            // SAFETY: `Sid` points into the buffer; copy it out before it drops.
            let len = unsafe { GetLengthSid(entry.Sid) } as usize;
            let mut copy = vec![0u8; len];
            unsafe { ptr::copy_nonoverlapping(entry.Sid as *const u8, copy.as_mut_ptr(), len) };
            return Some(copy);
        }
    }
    None
}

/// `Everyone` (S-1-1-0) in self-relative form.
fn everyone_bytes() -> Vec<u8> {
    vec![0x01, 0x01, 0, 0, 0, 0, 0, 5, 0x01, 0, 0, 0]
}

/// Set the token's default DACL: logon SID full control, `OWNER RIGHTS` only
/// `READ_CONTROL`.
fn set_default_dacl(token: HANDLE, logon: PSID) -> Result<(), String> {
    // S-1-3-4 = OWNER RIGHTS.
    let mut owner_rights = [0x01u8, 0x01, 0, 0, 0, 0, 0, 3, 0x04, 0, 0, 0];
    let entries = [
        (logon, GENERIC_ALL),
        (owner_rights.as_mut_ptr() as PSID, READ_CONTROL),
    ]
    .map(|(sid, access)| EXPLICIT_ACCESS_W {
        grfAccessPermissions: access,
        grfAccessMode: GRANT_ACCESS,
        grfInheritance: 0,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: ptr::null_mut(),
            MultipleTrusteeOperation: 0,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_UNKNOWN,
            ptstrName: sid as *mut u16,
        },
    });

    let mut dacl: *mut ACL = ptr::null_mut();
    // SAFETY: two valid entries, no old DACL.
    let code = unsafe {
        SetEntriesInAclW(
            entries.len() as u32,
            entries.as_ptr(),
            ptr::null(),
            &mut dacl,
        )
    };
    if code != ERROR_SUCCESS {
        return Err(format!(
            "SetEntriesInAcl (default DACL): {}",
            error_text(code)
        ));
    }
    let mut info = TokenDefaultDaclInfo { default_dacl: dacl };
    // SAFETY: the structure matches `TOKEN_DEFAULT_DACL`.
    let ok = unsafe {
        SetTokenInformation(
            token,
            TokenDefaultDacl,
            &mut info as *mut _ as *mut core::ffi::c_void,
            std::mem::size_of::<TokenDefaultDaclInfo>() as u32,
        )
    };
    // SAFETY: the DACL is owned here.
    unsafe { LocalFree(dacl as HLOCAL) };
    if ok == 0 {
        return Err(format!(
            "SetTokenInformation(TokenDefaultDacl): {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// `TOKEN_DEFAULT_DACL` argument shape.
#[repr(C)]
struct TokenDefaultDaclInfo {
    default_dacl: *mut ACL,
}

/// Enable one privilege on `token`.
fn enable_single_privilege(token: HANDLE, name: &str) -> Result<(), String> {
    use windows_sys::Win32::Foundation::LUID;
    use windows_sys::Win32::Security::{
        AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, TOKEN_PRIVILEGES,
    };

    let mut luid = LUID {
        LowPart: 0,
        HighPart: 0,
    };
    // SAFETY: the name is NUL-terminated and `luid` is a valid out pointer.
    if unsafe { LookupPrivilegeValueW(ptr::null(), wide(name).as_ptr(), &mut luid) } == 0 {
        return Err(format!(
            "LookupPrivilegeValue({name}): {}",
            std::io::Error::last_os_error()
        ));
    }
    let state = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };
    // SAFETY: the token was opened with TOKEN_ADJUST_PRIVILEGES.
    let ok =
        unsafe { AdjustTokenPrivileges(token, 0, &state, 0, ptr::null_mut(), ptr::null_mut()) };
    if ok == 0 {
        return Err(format!(
            "AdjustTokenPrivileges({name}): {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Child process
// ---------------------------------------------------------------------------

/// Private desktop so `USER32`/`SHELL32` initialization works under the
/// restricted token. Best effort: the default desktop is used on failure.
struct PrivateDesktop {
    handle: HANDLE,
    name: Vec<u16>,
}

impl Drop for PrivateDesktop {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            // SAFETY: the handle is owned by this wrapper.
            unsafe { CloseDesktop(self.handle) };
        }
    }
}

fn create_private_desktop(logon: Option<&[u8]>) -> Option<PrivateDesktop> {
    let logon = logon?;
    let name = format!(
        "RpiSandboxDesktop-{}-{:x}",
        std::process::id(),
        state::nonce()
    );
    let wide_name = wide(&name);
    // SAFETY: `wide_name` is NUL-terminated and an empty security descriptor
    // (NULL) inherits the creator's default.
    let handle = unsafe {
        CreateDesktopW(
            wide_name.as_ptr(),
            ptr::null(),
            ptr::null(),
            0,
            DESKTOP_CREATE_ACCESS,
            ptr::null(),
        )
    };
    if handle.is_null() {
        eprintln!(
            "warning: sandbox: cannot create a private desktop: {}; using the default desktop",
            std::io::Error::last_os_error()
        );
        return None;
    }

    // Grant the logon SID full desktop access.
    let entry = EXPLICIT_ACCESS_W {
        grfAccessPermissions: DESKTOP_ALL_ACCESS,
        grfAccessMode: GRANT_ACCESS,
        grfInheritance: 0,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: ptr::null_mut(),
            MultipleTrusteeOperation: 0,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_UNKNOWN,
            ptstrName: logon.as_ptr() as PSID as *mut u16,
        },
    };
    let mut dacl: *mut ACL = ptr::null_mut();
    // SAFETY: one valid entry; no old DACL.
    let code = unsafe { SetEntriesInAclW(1, &entry, ptr::null(), &mut dacl) };
    if code != ERROR_SUCCESS {
        eprintln!(
            "warning: sandbox: SetEntriesInAcl (desktop): {}",
            error_text(code)
        );
        // SAFETY: the handle is owned here.
        unsafe { CloseDesktop(handle) };
        return None;
    }
    // SAFETY: `dacl` is valid and the handle was created with WRITE_DAC.
    let code = unsafe {
        SetSecurityInfo(
            handle,
            SE_WINDOW_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            dacl as *const ACL,
            ptr::null_mut(),
        )
    };
    // SAFETY: the DACL is owned here.
    unsafe { LocalFree(dacl as HLOCAL) };
    if code != ERROR_SUCCESS {
        eprintln!(
            "warning: sandbox: SetSecurityInfo (desktop): {}; using the default desktop",
            error_text(code)
        );
        // SAFETY: the handle is owned here.
        unsafe { CloseDesktop(handle) };
        return None;
    }

    Some(PrivateDesktop {
        handle,
        name: wide_name,
    })
}

/// Build the `CREATE_UNICODE_ENVIRONMENT` block.
fn environment_block(env: &rpi_sandbox_core::SandboxEnv) -> Vec<u16> {
    let merged = env.overlay(std::env::vars_os());
    let mut block: Vec<u16> = Vec::new();
    for (name, value) in merged {
        if name.is_empty() {
            continue;
        }
        block.extend(name.encode_wide());
        block.push('=' as u16);
        block.extend(value.encode_wide());
        block.push(0);
    }
    block.push(0);
    block
}

/// Quote one argument per `CommandLineToArgvW` rules.
fn append_argument(cmdline: &mut String, argument: &str) {
    let needs_quotes = argument.is_empty()
        || argument
            .chars()
            .any(|character| character.is_whitespace() || character == '"');
    if !needs_quotes {
        cmdline.push_str(argument);
        return;
    }
    cmdline.push('"');
    let mut backslashes = 0usize;
    for character in argument.chars() {
        match character {
            '\\' => backslashes += 1,
            '"' => {
                cmdline.push_str(&"\\".repeat(backslashes * 2 + 1));
                cmdline.push('"');
                backslashes = 0;
            }
            other => {
                cmdline.push_str(&"\\".repeat(backslashes));
                backslashes = 0;
                cmdline.push(other);
            }
        }
    }
    cmdline.push_str(&"\\".repeat(backslashes * 2));
    cmdline.push('"');
}

fn command_line(program: &Path, args: &[String]) -> Vec<u16> {
    let mut text = String::new();
    append_argument(&mut text, &program.to_string_lossy());
    for argument in args {
        text.push(' ');
        append_argument(&mut text, argument);
    }
    let mut wide: Vec<u16> = text.encode_utf16().collect();
    wide.push(0);
    wide
}

fn spawn_child(
    token: &PrimaryToken,
    spec: &LaunchSpec,
    environment: &[u16],
) -> Result<u32, String> {
    let program = wide(spec.program.as_os_str());
    let cwd = wide(spec.cwd.as_os_str());
    let mut cmdline = command_line(&spec.program, &spec.args);
    let logon = logon_sid_from_current();
    let mut desktop = create_private_desktop(logon.as_deref());

    let mut startup = STARTUPINFOW::default();
    startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    startup.dwFlags = STARTF_USESTDHANDLES;
    // SAFETY: the standard handle getters are always valid for a console app.
    unsafe {
        startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
        startup.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
        startup.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    }
    if let Some(desktop) = desktop.as_mut() {
        startup.lpDesktop = desktop.name.as_mut_ptr();
    }

    let mut process = PROCESS_INFORMATION::default();
    // SAFETY: every pointer refers to a live, correctly sized buffer for the
    // duration of the call. The environment is a Unicode block because
    // CREATE_UNICODE_ENVIRONMENT is set.
    let created = unsafe {
        CreateProcessAsUserW(
            token.0,
            program.as_ptr(),
            cmdline.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            1,
            CREATE_UNICODE_ENVIRONMENT,
            environment.as_ptr() as *const core::ffi::c_void,
            cwd.as_ptr(),
            &startup,
            &mut process,
        )
    };
    if created == 0 {
        return Err(format!(
            "CreateProcessAsUser failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    // SAFETY: both handles are owned by this function.
    unsafe { WaitForSingleObject(process.hProcess, INFINITE) };
    let mut code: u32 = 1;
    // SAFETY: the process handle is valid.
    unsafe {
        GetExitCodeProcess(process.hProcess, &mut code);
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
    }
    Ok(code)
}

/// Logon SID of the current process, for the private desktop.
fn logon_sid_from_current() -> Option<Vec<u8>> {
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: the pseudo-handle is valid and the token is closed below.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return None;
    }
    let sid = logon_sid(token);
    // SAFETY: the token is owned here.
    unsafe { CloseHandle(token) };
    sid
}

// ---------------------------------------------------------------------------
// Console handler and public helpers
// ---------------------------------------------------------------------------

/// Ignore Ctrl+C in the launcher (the child owns the terminal) but clean up
/// ACLs before the console closes the process.
unsafe extern "system" fn console_handler(event: u32) -> i32 {
    match event {
        CTRL_C_EVENT | CTRL_BREAK_EVENT => 1, // handled: keep waiting
        CTRL_CLOSE_EVENT | CTRL_LOGOFF_EVENT | CTRL_SHUTDOWN_EVENT => {
            let mut audit = AuditLog::default();
            cleanup_pending(&mut audit);
            0
        }
        _ => 0,
    }
}

fn install_console_handler() {
    // SAFETY: the handler is a plain `extern "system"` function that only uses
    // owned state; registration is process-wide.
    unsafe { SetConsoleCtrlHandler(Some(console_handler), 1) };
}

/// Revoke ACLs left behind by this or earlier runs.
///
/// `--cleanup` does not need the original command line: journals carry their
/// own paths, and the belt-and-braces pass re-derives the same plan from the
/// policy.
pub fn cleanup(
    profile: &str,
    cwd: &Path,
    policy: &SandboxPolicy,
    read_roots: &[PathBuf],
) -> Result<(), String> {
    let mut audit = AuditLog::open(policy.audit_log.as_deref());
    sweep_journals(&mut audit);
    let sids = CapabilitySids::derive(profile, cwd)?;
    let plan = windows_plan::build_plan(policy);

    let mut failures = 0usize;
    for root in read_roots.iter().filter(|root| root.is_dir()) {
        if revoke_ace(root, sids.read, READ_EXEC_ALLOW, false).is_err() {
            failures += 1;
        }
    }
    for entry in &plan.allow {
        if revoke_ace(&entry.path, sids.write, entry.mask, false).is_err() {
            failures += 1;
        }
    }
    for entry in &plan.deny {
        if revoke_ace(&entry.path, sids.write, entry.mask, true).is_err() {
            failures += 1;
        }
    }
    if failures > 0 {
        Err(format!(
            "{failures} path(s) could not be cleaned; run with more privileges or check the audit log"
        ))
    } else {
        eprintln!(
            "sandbox: cleanup complete (read {read}, write {write})",
            read = sids.read_text,
            write = sids.write_text
        );
        Ok(())
    }
}

/// Print the capability SIDs for this profile and directory.
pub fn print_sids(profile: &str, cwd: &Path) {
    match CapabilitySids::derive(profile, cwd) {
        Ok(sids) => {
            println!("profile = {profile}");
            println!("cwd     = {}", cwd.display());
            println!("read    = {}", sids.read_text);
            println!("write   = {}", sids.write_text);
        }
        Err(error) => eprintln!("rpis: {error}"),
    }
}

/// Start the broker on its own thread; the main thread waits for the child.
fn start_broker(listener: Listener, config: BrokerConfig) {
    std::thread::spawn(move || match listener.accept() {
        Ok(conn) => {
            let read_half = match conn.try_clone() {
                Ok(half) => half,
                Err(error) => {
                    eprintln!("warning: sandbox broker cannot read its pipe: {error}");
                    return;
                }
            };
            let mut service = BrokerService::new(config);
            if let Err(error) = service.serve_connection(std::io::BufReader::new(read_half), conn) {
                eprintln!("warning: sandbox broker stopped: {error}");
            }
        }
        Err(error) => eprintln!("warning: sandbox broker accept failed: {error}"),
    });
}

/// Install the console handler and open the journal for this run.
fn begin_run() -> Result<(), String> {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(install_console_handler);
    begin_journal()
}

fn path_key(path: &Path) -> String {
    path.display().to_string()
}

fn wide(text: impl AsRef<OsStr>) -> Vec<u16> {
    text.as_ref()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn error_text(code: WIN32_ERROR) -> String {
    // SAFETY: `FormatMessage` is not used here to keep the surface small; the
    // numeric code plus the cached last error is enough for diagnostics.
    if code == ERROR_SUCCESS {
        "success".to_string()
    } else {
        format!("Win32 error {code} (last error {})", unsafe {
            GetLastError()
        })
    }
}
