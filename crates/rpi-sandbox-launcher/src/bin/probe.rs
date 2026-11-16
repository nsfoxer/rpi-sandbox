//! Test payload for the launcher integration tests.
//!
//! Both the Linux and the Windows suites point `rpis --rpi <this binary>` at
//! this program, so the assertions stay identical across platforms:
//!
//! ```text
//! rpi-sandbox-probe write  <path> <content>   write a file directly
//! rpi-sandbox-probe read   <path>             print a file
//! rpi-sandbox-probe spawn-write <path> <text> write from a grandchild
//! rpi-sandbox-probe set-acl <path>            try to widen a DACL (Windows)
//! rpi-sandbox-probe broker-hello              handshake with the broker
//! rpi-sandbox-probe broker-write <path> <t>   approve + write through the broker
//! rpi-sandbox-probe env <name>                print an environment variable
//! rpi-sandbox-probe exit <code>               exit with a specific code
//! ```

use std::path::Path;

use rpi_sandbox_core::{ApprovalScope, BrokerClient, WriteOp};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(command) = args.first().map(String::as_str) else {
        eprintln!("probe: missing command");
        std::process::exit(2);
    };
    let result = match command {
        "write" => write(&args),
        "read" => read(&args),
        "spawn-write" => spawn_write(&args),
        "set-acl" => set_acl(&args),
        "broker-hello" => broker_hello(),
        "broker-write" => broker_write(&args),
        "sleep" => sleep(&args),
        "hold" => hold(&args),
        "env" => print_env(&args),
        "exit" => exit(&args),
        other => Err(format!("probe: unknown command {other}")),
    };
    match result {
        Ok(()) => {}
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(1);
        }
    }
}

fn write(args: &[String]) -> Result<(), String> {
    let path = args.get(1).ok_or("probe: write needs a path")?;
    let content = args.get(2).map(String::as_str).unwrap_or("");
    std::fs::write(path, content).map_err(|error| format!("write {path}: {error}"))
}

fn read(args: &[String]) -> Result<(), String> {
    let path = args.get(1).ok_or("probe: read needs a path")?;
    let content = std::fs::read_to_string(path).map_err(|error| format!("read {path}: {error}"))?;
    print!("{content}");
    Ok(())
}

fn spawn_write(args: &[String]) -> Result<(), String> {
    let path = args.get(1).ok_or("probe: spawn-write needs a path")?;
    let content = args.get(2).map(String::as_str).unwrap_or("");
    let exe = std::env::current_exe().map_err(|error| format!("current_exe: {error}"))?;
    let status = std::process::Command::new(exe)
        .arg("write")
        .arg(path)
        .arg(content)
        .status()
        .map_err(|error| format!("spawn: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("grandchild write failed: {status}"))
    }
}

fn broker_client() -> Result<BrokerClient, String> {
    let socket = std::env::var_os(rpi_sandbox_core::protocol::env::SOCKET)
        .ok_or("probe: RPI_SANDBOX_SOCKET is not set")?;
    BrokerClient::connect(Path::new(&socket)).map_err(|error| format!("connect: {error}"))
}

fn broker_hello() -> Result<(), String> {
    let client = broker_client()?;
    let hello = client
        .hello("rpi-sandbox-probe", env!("CARGO_PKG_VERSION"))
        .map_err(|error| format!("hello: {error}"))?;
    println!(
        "sandbox={} profile={}",
        hello.sandbox.as_deref().unwrap_or("none"),
        hello.profile.as_deref().unwrap_or("none")
    );
    Ok(())
}

fn broker_write(args: &[String]) -> Result<(), String> {
    let raw = args.get(1).ok_or("probe: broker-write needs a path")?;
    let content = args.get(2).map(String::as_str).unwrap_or("");
    let absolute = std::path::absolute(raw).map_err(|error| format!("absolute: {error}"))?;
    let client = broker_client()?;
    client
        .approve(
            &absolute,
            &[WriteOp::Create, WriteOp::Overwrite],
            ApprovalScope::Session,
            false,
        )
        .map_err(|error| format!("approve: {error}"))?;
    client
        .write(&absolute, content.as_bytes())
        .map_err(|error| format!("write: {error}"))
}

/// Publish the broker endpoint on stdout, then stay alive for `millis`.
///
/// The integration tests read the first stdout line to learn the pipe name and
/// then connect from the unconfined test process.
fn hold(args: &[String]) -> Result<(), String> {
    use std::io::Write;
    let millis: u64 = args
        .get(1)
        .ok_or("probe: hold needs milliseconds")?
        .parse()
        .map_err(|error| format!("probe: invalid duration: {error}"))?;
    let socket = std::env::var(rpi_sandbox_core::protocol::env::SOCKET)
        .unwrap_or_else(|_| "none".to_string());
    println!("{socket}");
    std::io::stdout()
        .flush()
        .map_err(|error| format!("stdout: {error}"))?;
    std::thread::sleep(std::time::Duration::from_millis(millis));
    Ok(())
}

fn sleep(args: &[String]) -> Result<(), String> {
    let millis: u64 = args
        .get(1)
        .ok_or("probe: sleep needs milliseconds")?
        .parse()
        .map_err(|error| format!("probe: invalid duration: {error}"))?;
    std::thread::sleep(std::time::Duration::from_millis(millis));
    Ok(())
}

#[cfg(windows)]
fn set_acl(args: &[String]) -> Result<(), String> {
    use windows_sys::Win32::Security::Authorization::{SetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;

    let path = args.get(1).ok_or("probe: set-acl needs a path")?;
    let wide: Vec<u16> = std::ffi::OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // A NULL DACL grants everyone full control: exactly the escalation the
    // sandbox must prevent.
    let code = unsafe {
        SetNamedSecurityInfoW(
            wide.as_ptr() as *mut u16,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null_mut(),
        )
    };
    if code == 0 {
        Err("set-acl succeeded: the sandbox did not prevent a DACL rewrite".to_string())
    } else {
        println!("set-acl denied ({code})");
        Ok(())
    }
}

#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;

#[cfg(not(windows))]
fn set_acl(_args: &[String]) -> Result<(), String> {
    Err("probe: set-acl is only meaningful on Windows".to_string())
}

fn print_env(args: &[String]) -> Result<(), String> {
    let name = args.get(1).ok_or("probe: env needs a variable name")?;
    match std::env::var(name) {
        Ok(value) => {
            print!("{value}");
            Ok(())
        }
        Err(_) => Err(format!("probe: {name} is not set")),
    }
}

fn exit(args: &[String]) -> Result<(), String> {
    let code: i32 = args
        .get(1)
        .ok_or("probe: exit needs a code")?
        .parse()
        .map_err(|error| format!("probe: invalid exit code: {error}"))?;
    std::process::exit(code)
}
