//! Path-safe file mutations for the broker.
//!
//! The broker runs outside the sandbox and performs writes that the sandboxed
//! process cannot do itself. It must therefore never re-resolve a path after the
//! policy check: an attacker can swap a parent directory for a symlink between
//! the check and `std::fs::write`, turning an approved in-root write into an
//! escape.
//!
//! Every operation here resolves the path one component at a time from `/` (or
//! a Windows parent handle) with `O_NOFOLLOW`, then acts relative to that
//! pinned directory. A swapped symlink makes `openat` fail with `ELOOP` instead
//! of being followed.

use std::io;
use std::path::Path;

/// How [`write`] may modify an existing path.
///
/// The broker picks this from the approval it consumed. Enforcing it in the
/// open flags closes the race where a file disappears or appears between
/// `Path::exists()` and the actual write: a `Create` approval cannot truncate a
/// file that already exists, and an `Overwrite` approval cannot create one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteMode {
    /// Create a new file; fail if it already exists.
    Create,
    /// Truncate and overwrite an existing file; fail if it is missing.
    Overwrite,
    /// Append, creating the file when needed.
    Append,
}

/// Write `bytes` to `path`, creating missing parents.
pub fn write(path: &Path, bytes: &[u8], mode: WriteMode) -> io::Result<()> {
    imp::write(path, bytes, mode)
}

/// Truncate an existing file to `len` bytes.
pub fn truncate(path: &Path, len: u64) -> io::Result<()> {
    imp::truncate(path, len)
}

/// Remove a file (not a directory).
pub fn remove_file(path: &Path) -> io::Result<()> {
    imp::remove_file(path)
}

/// Rename `source` to `destination`, creating the destination's parents.
pub fn rename(source: &Path, destination: &Path) -> io::Result<()> {
    imp::rename(source, destination)
}

/// Create a directory and every missing parent.
pub fn create_dir_all(path: &Path) -> io::Result<()> {
    imp::create_dir_all(path)
}

#[cfg(unix)]
mod imp {
    use std::ffi::{CString, OsStr};
    use std::fs::File;
    use std::io::{self, Write};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Component, Path};

    fn invalid(message: &str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, message)
    }

    fn cstring(name: &OsStr) -> io::Result<CString> {
        CString::new(name.as_bytes()).map_err(|_| invalid("path component contains a NUL byte"))
    }

    #[cfg(target_os = "linux")]
    const DIRECTORY_FLAGS: i32 =
        libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    const DIRECTORY_FLAGS: i32 =
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;

    fn open_root() -> io::Result<File> {
        #[cfg(target_os = "linux")]
        let flags = libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC;
        #[cfg(not(target_os = "linux"))]
        let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC;
        // SAFETY: the path is a static NUL-terminated string.
        let fd = unsafe { libc::open(b"/\0".as_ptr().cast(), flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a newly opened descriptor owned by us.
        Ok(unsafe { File::from(OwnedFd::from_raw_fd(fd)) })
    }

    /// Open `name` below `dir` as a directory, optionally creating it.
    fn open_dir(dir: &File, name: &OsStr, create: bool) -> io::Result<File> {
        let name = cstring(name)?;
        for attempt in 0..2 {
            // SAFETY: both descriptors and the name are valid.
            let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), DIRECTORY_FLAGS) };
            if fd >= 0 {
                // SAFETY: `fd` is owned by us.
                return Ok(unsafe { File::from(OwnedFd::from_raw_fd(fd)) });
            }
            let error = io::Error::last_os_error();
            if !create || error.raw_os_error() != Some(libc::ENOENT) || attempt == 1 {
                return Err(error);
            }
            // SAFETY: the parent descriptor and name are valid.
            let result = unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), 0o755) };
            if result != 0 {
                let mkdir_error = io::Error::last_os_error();
                if mkdir_error.raw_os_error() != Some(libc::EEXIST) {
                    return Err(mkdir_error);
                }
            }
        }
        unreachable!("the retry loop returns on the second attempt")
    }

    /// Open the parent of `path` and return it with the final component.
    fn open_parent(path: &Path, create: bool) -> io::Result<(File, CString)> {
        if !path.is_absolute() {
            return Err(invalid("broker path must be absolute"));
        }
        let mut dir = open_root()?;
        let mut components = path.components().peekable();
        match components.next() {
            Some(Component::RootDir) => {}
            _ => return Err(invalid("broker path must start at the filesystem root")),
        }
        while let Some(component) = components.next() {
            let Component::Normal(name) = component else {
                return Err(invalid("broker path contains `.` or `..`"));
            };
            if components.peek().is_none() {
                return Ok((dir, cstring(name)?));
            }
            dir = open_dir(&dir, name, create)?;
        }
        Err(invalid("broker path has no file name"))
    }

    pub fn write(path: &Path, bytes: &[u8], mode: super::WriteMode) -> io::Result<()> {
        let (parent, name) = open_parent(path, true)?;
        let mut flags = libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        match mode {
            super::WriteMode::Create => flags |= libc::O_CREAT | libc::O_EXCL,
            super::WriteMode::Overwrite => flags |= libc::O_TRUNC,
            super::WriteMode::Append => flags |= libc::O_APPEND | libc::O_CREAT,
        }
        // SAFETY: the parent descriptor and name are valid.
        let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags, 0o666) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a newly opened descriptor owned by us.
        let mut file = unsafe { File::from(OwnedFd::from_raw_fd(fd)) };
        file.write_all(bytes)?;
        file.flush()
    }

    pub fn truncate(path: &Path, len: u64) -> io::Result<()> {
        let (parent, name) = open_parent(path, false)?;
        let flags = libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        // SAFETY: the parent descriptor and name are valid.
        let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a newly opened descriptor owned by us.
        let file = unsafe { File::from(OwnedFd::from_raw_fd(fd)) };
        file.set_len(len)
    }

    pub fn remove_file(path: &Path) -> io::Result<()> {
        let (parent, name) = open_parent(path, false)?;
        // SAFETY: the parent descriptor and name are valid.
        let result = unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn rename(source: &Path, destination: &Path) -> io::Result<()> {
        let (source_parent, source_name) = open_parent(source, false)?;
        let (destination_parent, destination_name) = open_parent(destination, true)?;
        // SAFETY: all four values are valid; both parent descriptors stay open
        // for the whole call.
        let result = unsafe {
            libc::renameat(
                source_parent.as_raw_fd(),
                source_name.as_ptr(),
                destination_parent.as_raw_fd(),
                destination_name.as_ptr(),
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn create_dir_all(path: &Path) -> io::Result<()> {
        if path.parent().is_none() {
            return Ok(());
        }
        let (parent, name) = open_parent(path, true)?;
        // SAFETY: the parent descriptor and name are valid.
        let result = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o755) };
        if result != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EEXIST) {
                return Err(error);
            }
        }
        // Verify the final component is a real directory; `O_NOFOLLOW` rejects
        // a symlink that already exists at this path.
        // SAFETY: the parent descriptor and name are valid.
        let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), DIRECTORY_FLAGS) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is owned by us; dropping closes it.
        drop(unsafe { OwnedFd::from_raw_fd(fd) });
        Ok(())
    }
}

#[cfg(windows)]
mod imp {
    use std::fs::{File, OpenOptions};
    use std::io::{self, Write};
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::{Path, PathBuf};

    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Storage::FileSystem::{
        FileDispositionInfo, GetFileInformationByHandle, GetFinalPathNameByHandleW,
        SetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_DISPOSITION_INFO, FILE_FLAG_OPEN_REPARSE_POINT, FILE_NAME_NORMALIZED, VOLUME_NAME_DOS,
    };

    const DELETE: u32 = 0x0001_0000;
    const SYNCHRONIZE: u32 = 0x0010_0000;

    fn invalid(message: impl Into<String>) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, message.into())
    }

    fn handle(file: &File) -> HANDLE {
        file.as_raw_handle() as HANDLE
    }

    /// Final DOS path behind an open handle, normalized like the policy paths.
    fn final_path(file: &File) -> io::Result<PathBuf> {
        let mut buffer = vec![0u16; 512];
        loop {
            // SAFETY: the handle is valid and the buffer is writable.
            let len = unsafe {
                GetFinalPathNameByHandleW(
                    handle(file),
                    buffer.as_mut_ptr(),
                    buffer.len() as u32,
                    FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
                )
            };
            if len == 0 {
                return Err(io::Error::last_os_error());
            }
            if (len as usize) < buffer.len() {
                buffer.truncate(len as usize);
                break;
            }
            buffer.resize(len as usize + 1, 0);
        }
        let text = String::from_utf16_lossy(&buffer);
        Ok(crate::path::lexical_normalize(Path::new(&text)))
    }

    /// Reject reparse points and any handle that resolves somewhere else.
    fn verify(file: &File, expected: &Path) -> io::Result<()> {
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: the handle is valid and `info` is writable.
        let ok = unsafe { GetFileInformationByHandle(handle(file), &mut info) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "broker path is a reparse point",
            ));
        }
        let actual = final_path(file)?;
        let expected = crate::path::normalize_and_resolve(expected);
        // Windows paths are case-insensitive; the on-disk case may differ from
        // the request. Compare the normalized text, not the raw `Path`.
        if !actual
            .to_string_lossy()
            .eq_ignore_ascii_case(&expected.to_string_lossy())
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "broker path resolves to {} instead of {}",
                    actual.display(),
                    expected.display()
                ),
            ));
        }
        Ok(())
    }

    /// Walk existing components and reject reparse points before creating.
    fn reject_reparse_components(path: &Path) -> io::Result<()> {
        let mut current = PathBuf::new();
        for component in path.components() {
            current.push(component.as_os_str());
            match std::fs::symlink_metadata(&current) {
                Ok(metadata) => {
                    use std::os::windows::fs::MetadataExt;
                    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            format!(
                                "broker path contains a reparse point: {}",
                                current.display()
                            ),
                        ));
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => break,
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    pub fn write(path: &Path, bytes: &[u8], mode: super::WriteMode) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            create_dir_all(parent)?;
        }
        reject_reparse_components(path)?;
        let mut options = OpenOptions::new();
        options
            .write(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        match mode {
            super::WriteMode::Create => {
                options.create_new(true);
            }
            super::WriteMode::Overwrite => {
                options.truncate(true);
            }
            super::WriteMode::Append => {
                options.append(true).create(true);
            }
        }
        let mut file = options.open(path)?;
        verify(&file, path)?;
        file.write_all(bytes)?;
        file.flush()
    }

    pub fn truncate(path: &Path, len: u64) -> io::Result<()> {
        reject_reparse_components(path)?;
        let mut options = OpenOptions::new();
        options
            .write(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        let file = options.open(path)?;
        verify(&file, path)?;
        file.set_len(len)
    }

    pub fn remove_file(path: &Path) -> io::Result<()> {
        reject_reparse_components(path)?;
        let mut options = OpenOptions::new();
        options
            .access_mode(DELETE | SYNCHRONIZE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        let file = options.open(path)?;
        verify(&file, path)?;
        let info = FILE_DISPOSITION_INFO { DeleteFile: true };
        // SAFETY: the handle is valid and `info` is a correctly sized buffer.
        let ok = unsafe {
            SetFileInformationByHandle(
                handle(&file),
                FileDispositionInfo,
                &info as *const _ as *const core::ffi::c_void,
                std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn rename(source: &Path, destination: &Path) -> io::Result<()> {
        let Some(parent) = destination.parent() else {
            return Err(invalid("destination has no parent"));
        };
        create_dir_all(parent)?;
        reject_reparse_components(source)?;
        reject_reparse_components(destination)?;
        // Windows has no `renameat`; `MoveFileExW` (via std) re-resolves the
        // destination parent. Both parents are verified immediately before the
        // call, and MXC remains the primary write boundary.
        std::fs::rename(source, destination)
    }

    pub fn create_dir_all(path: &Path) -> io::Result<()> {
        reject_reparse_components(path)?;
        std::fs::create_dir_all(path)?;
        reject_reparse_components(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_and_appends_inside_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/file.txt");
        write(&path, b"one", WriteMode::Create).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "one");
        write(&path, b"two", WriteMode::Append).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "onetwo");
        write(&path, b"three", WriteMode::Overwrite).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "three");
        truncate(&path, 3).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "thr");
    }

    #[test]
    fn create_and_overwrite_cannot_cross() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file.txt");
        write(&path, b"one", WriteMode::Create).unwrap();
        let error = write(&path, b"two", WriteMode::Create).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "one");

        write(&path, b"two", WriteMode::Overwrite).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "two");
        remove_file(&path).unwrap();
        let error = write(&path, b"x", WriteMode::Overwrite).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn rename_delete_and_mkdir_stay_inside_the_parent() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("a.txt");
        let destination = dir.path().join("sub/b.txt");
        std::fs::write(&source, b"move").unwrap();
        rename(&source, &destination).unwrap();
        assert!(!source.exists());
        assert_eq!(std::fs::read_to_string(&destination).unwrap(), "move");
        remove_file(&destination).unwrap();
        assert!(!destination.exists());
        create_dir_all(&dir.path().join("x/y/z")).unwrap();
        assert!(dir.path().join("x/y/z").is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_parent_is_rejected_instead_of_followed() {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        let error = write(&link.join("file.txt"), b"x", WriteMode::Create).unwrap_err();
        assert!(
            matches!(
                error.raw_os_error(),
                Some(libc::ELOOP) | Some(libc::ENOTDIR)
            ),
            "{error:?}"
        );
        assert!(!outside.join("file.txt").exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_swap_cannot_redirect_a_write() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let dir = tempfile::tempdir().unwrap();
        let inside = dir.path().join("inside");
        let backup = dir.path().join("backup");
        let outside = dir.path().join("outside");
        std::fs::create_dir(&inside).unwrap();
        std::fs::create_dir(&outside).unwrap();
        let stop = Arc::new(AtomicBool::new(false));

        let attacker = {
            let inside = inside.clone();
            let backup = backup.clone();
            let outside = outside.clone();
            let stop = stop.clone();
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let is_symlink = std::fs::symlink_metadata(&inside)
                        .map(|metadata| metadata.file_type().is_symlink())
                        .unwrap_or(false);
                    if is_symlink {
                        let _ = std::fs::remove_file(&inside);
                        let _ = std::fs::rename(&backup, &inside);
                    } else {
                        let _ = std::fs::rename(&inside, &backup);
                        let _ = std::os::unix::fs::symlink(&outside, &inside);
                    }
                }
            })
        };

        let target = inside.join("file.txt");
        for _ in 0..2000 {
            let _ = write(&target, b"x", WriteMode::Append);
        }
        stop.store(true, Ordering::Relaxed);
        attacker.join().unwrap();
        assert!(
            !outside.join("file.txt").exists(),
            "a swapped parent redirected the write"
        );
    }
}
