//! `rpi-sandbox` launcher.
//!
//! Phase 0 only reserves the crate. Phase 1 adds argument parsing, the broker
//! socket, the fork, the platform backend, and `exec rpi`. The launcher is the
//! only component allowed to claim kernel-enforced whole-process isolation.

fn main() {
    eprintln!("rpi-sandbox: launcher is not implemented yet (Phase 1)");
    std::process::exit(2);
}
