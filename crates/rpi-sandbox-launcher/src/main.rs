//! Launcher entry point.
//!
//! Parsing, policy compilation, target resolution, and environment construction
//! live in [`args`] and [`setup`]; the platform modules only compile a plan and
//! launch the target.

mod args;
mod setup;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(windows)]
mod windows;

#[cfg(any(target_os = "linux", windows))]
fn main() {
    let args = match args::parse_args(std::env::args_os().skip(1)) {
        Ok(args) => args,
        Err(args::ParseError::Help) => {
            println!("{}", args::HELP);
            return;
        }
        Err(args::ParseError::Version) => {
            println!("rpis {}", env!("CARGO_PKG_VERSION"));
            return;
        }
        Err(args::ParseError::Message(message)) => {
            eprintln!("rpis: {message}\n\n{}", args::HELP);
            std::process::exit(2);
        }
    };

    match setup::run(args) {
        Ok(code) => std::process::exit(code),
        Err(message) => {
            eprintln!("rpis: {message}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
fn main() {
    eprintln!("rpis: this build supports Linux and Windows; macOS is Phase 3");
    std::process::exit(1);
}
