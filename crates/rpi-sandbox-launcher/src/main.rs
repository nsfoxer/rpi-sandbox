//! `rpi-sandbox` launcher.
//!
//! The launcher is the only component that can claim whole-process isolation:
//! it compiles the policy, creates the broker socket, forks the unconfined
//! broker, applies the platform backend to itself, and then `exec`s the target
//! command. Kernel domains are inherited by every thread, plugin, shell, and
//! grandchild created afterwards.

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
fn main() {
    linux::main();
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("rpi-sandbox: this build only supports Linux (Phase 1)");
    std::process::exit(1);
}
