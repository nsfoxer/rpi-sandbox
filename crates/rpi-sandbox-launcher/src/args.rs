//! Command-line parsing shared by every platform backend.
//!
//! Everything up to the first unrecognized argument belongs to `rpis`; the
//! rest is forwarded to `rpi` verbatim so `rpis -p "..."` works without `--`.

use std::ffi::OsString;
use std::path::PathBuf;

use rpi_sandbox_core::SandboxMode;

pub const HELP: &str = "\
rpis — run rpi inside a whole-process filesystem sandbox

Usage:
  rpis [options] [rpi args...]

The rpi binary is resolved automatically:
  1. --rpi <path>
  2. RPI_SANDBOX_RPI
  3. `rpi` (or `rpi.exe`) next to this executable
  4. `rpi` on PATH

Options:
  --rpi <path>         rpi executable to launch
  --no-extension       Do not inject the DLL next to rpis (installed plugins still load)
  --profile <name>     Profile label advertised on the broker
  --config <path>      Global settings file (default: ~/.rpi/agent/sandbox.json)
  --write <dir>        Extra writable directory (repeatable)
  --readonly <path>    Keep a path read-only inside writable roots (repeatable)
  --read <dir>         Extra read root (Windows only; repeatable)
  --mode <mode>        auto | required | off (default: required)
  --audit <path>       Broker audit log
  --no-broker          Do not start the approval broker
  --no-sandbox         Run without isolation (explicit bypass)
  --print-plan         Print the backend plan and exit without launching
  --                   Pass the rest verbatim to rpi
  -h, --help           Show this help
  -V, --version        Show the rpis version

Examples:
  rpis
  rpis -p \"summarize this repository\"
  rpis --write /srv/data -- rpi --resume
  rpis -- --help

The sandbox is opt-in: invoking rpis is the explicit request. The default
failure mode is `required`; use `--mode auto` (or `\"mode\": \"auto\"` in the
config) to allow degrading when the backend is unavailable. Pass --no-sandbox
or set RPI_SANDBOX=0 to bypass it for one run.";

/// Subcommands that legitimately write outside the workspace.
pub const MAINTENANCE: [&str; 12] = [
    "install",
    "uninstall",
    "auth",
    "update",
    "extension",
    "package",
    "resource",
    "events",
    "session",
    "dev",
    "dev-local",
    "__rpi_dev_cleanup",
];

/// Parsed command line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Args {
    pub rpi: Option<PathBuf>,
    pub no_extension: bool,
    pub profile: String,
    pub config: Option<PathBuf>,
    pub writable: Vec<String>,
    pub readonly: Vec<String>,
    pub read_roots: Vec<String>,
    pub mode: Option<SandboxMode>,
    pub audit: Option<PathBuf>,
    pub broker: bool,
    pub enabled: Option<bool>,
    pub print_plan: bool,
    pub target: Vec<String>,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            rpi: None,
            no_extension: false,
            profile: "default".to_string(),
            config: None,
            writable: Vec::new(),
            readonly: Vec::new(),
            read_roots: Vec::new(),
            mode: None,
            audit: None,
            broker: true,
            enabled: None,
            print_plan: false,
            target: Vec::new(),
        }
    }
}

/// Outcome of parsing the command line.
#[derive(Debug)]
pub enum ParseError {
    Help,
    Version,
    Message(String),
}

fn take_value<I: Iterator<Item = OsString>>(
    iter: &mut I,
    name: &str,
) -> Result<String, ParseError> {
    iter.next()
        .map(|value| value.to_string_lossy().into_owned())
        .ok_or_else(|| ParseError::Message(format!("{name} requires a value")))
}

/// Parse `rpis` arguments.
pub fn parse_args<I: Iterator<Item = OsString>>(args: I) -> Result<Args, ParseError> {
    let mut parsed = Args::default();
    let mut iter = args;
    while let Some(arg) = iter.next() {
        let text = arg.to_string_lossy().into_owned();
        if text == "--" {
            parsed.target = iter
                .map(|value| value.to_string_lossy().into_owned())
                .collect();
            return Ok(parsed);
        }
        match text.as_str() {
            "-h" | "--help" => return Err(ParseError::Help),
            "-V" | "--version" => return Err(ParseError::Version),
            "--rpi" => parsed.rpi = Some(PathBuf::from(take_value(&mut iter, "--rpi")?)),
            "--no-extension" => parsed.no_extension = true,
            "--profile" => parsed.profile = take_value(&mut iter, "--profile")?,
            "--config" => parsed.config = Some(PathBuf::from(take_value(&mut iter, "--config")?)),
            "--write" => parsed.writable.push(take_value(&mut iter, "--write")?),
            "--readonly" => parsed.readonly.push(take_value(&mut iter, "--readonly")?),
            "--read" => parsed.read_roots.push(take_value(&mut iter, "--read")?),
            "--mode" => {
                let mode = take_value(&mut iter, "--mode")?;
                parsed.mode = Some(match mode.as_str() {
                    "auto" => SandboxMode::Auto,
                    "required" => SandboxMode::Required,
                    "off" => SandboxMode::Off,
                    other => {
                        return Err(ParseError::Message(format!(
                            "unknown mode `{other}`; expected auto, required, or off"
                        )))
                    }
                });
            }
            "--audit" => parsed.audit = Some(PathBuf::from(take_value(&mut iter, "--audit")?)),
            "--no-broker" => parsed.broker = false,
            "--broker" => parsed.broker = true,
            "--no-sandbox" => parsed.enabled = Some(false),
            "--sandbox" => parsed.enabled = Some(true),
            "--print-plan" => parsed.print_plan = true,
            // Everything from the first unrecognized argument onwards belongs
            // to rpi, so `rpis -p "..."` works without a `--` separator.
            other => {
                parsed.target.push(other.to_string());
                parsed
                    .target
                    .extend(iter.map(|value| value.to_string_lossy().into_owned()));
                return Ok(parsed);
            }
        }
    }
    Ok(parsed)
}

/// Whether the target starts with a maintenance subcommand.
pub fn maintenance_bypass(target: &[String]) -> Option<&'static str> {
    // `--export` only reads a finished session file and writes one output; it
    // never runs a model session, so it stays outside the sandbox like the
    // other maintenance commands.
    if target
        .iter()
        .any(|arg| arg == "--export" || arg.starts_with("--export="))
    {
        return Some("export");
    }
    // `rpis <subcommand> ...`: maintenance commands are the first rpi argument.
    let first = target.first()?;
    MAINTENANCE
        .contains(&first.as_str())
        .then_some("maintenance command")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Result<Args, ParseError> {
        parse_args(values.iter().map(OsString::from))
    }

    #[test]
    fn parses_documented_options() {
        let parsed = args(&[
            "--rpi",
            "/usr/bin/rpi",
            "--no-extension",
            "--profile",
            "work",
            "--write",
            "/srv/data",
            "--write",
            "/tmp/out",
            "--readonly",
            "/srv/secrets",
            "--read",
            "/srv/bin",
            "--mode",
            "required",
            "--audit",
            "/tmp/audit.jsonl",
            "--no-broker",
            "-p",
            "hello",
        ])
        .unwrap();
        assert_eq!(parsed.rpi, Some(PathBuf::from("/usr/bin/rpi")));
        assert!(parsed.no_extension);
        assert_eq!(parsed.profile, "work");
        assert_eq!(parsed.writable, ["/srv/data", "/tmp/out"]);
        assert_eq!(parsed.readonly, ["/srv/secrets"]);
        assert_eq!(parsed.read_roots, ["/srv/bin"]);
        assert_eq!(parsed.mode, Some(SandboxMode::Required));
        assert_eq!(parsed.audit, Some(PathBuf::from("/tmp/audit.jsonl")));
        assert!(!parsed.broker);
        // `-p` is not a launcher option, so everything from there goes to rpi.
        assert_eq!(parsed.target, ["-p", "hello"]);
    }

    #[test]
    fn parses_the_plan_action() {
        let parsed = args(&["--print-plan"]).unwrap();
        assert!(parsed.print_plan);
        assert!(parsed.target.is_empty());
    }

    #[test]
    fn rpis_alone_is_valid() {
        assert_eq!(args(&[]).unwrap().target, Vec::<String>::new());
        assert_eq!(
            args(&["--profile", "x"]).unwrap().target,
            Vec::<String>::new()
        );
        assert!(matches!(args(&["--write"]), Err(ParseError::Message(_))));
    }

    #[test]
    fn unknown_arguments_start_the_rpi_command_line() {
        let parsed = args(&["--allow-everything", "value", "-p", "hi"]).unwrap();
        assert_eq!(parsed.target, ["--allow-everything", "value", "-p", "hi"]);
    }

    #[test]
    fn double_dash_forwards_verbatim() {
        let parsed = args(&["--write", "/srv/data", "--", "--sandbox", "-p", "hi"]).unwrap();
        assert_eq!(parsed.writable, ["/srv/data"]);
        assert_eq!(parsed.target, ["--sandbox", "-p", "hi"]);
    }

    #[test]
    fn maintenance_commands_bypass() {
        for command in MAINTENANCE {
            assert_eq!(
                maintenance_bypass(&[command.to_string()]),
                Some("maintenance command"),
                "{command} must bypass"
            );
        }
        assert_eq!(
            maintenance_bypass(&["-p".to_string(), "hi".to_string()]),
            None
        );
        assert_eq!(
            maintenance_bypass(&["--local-only".to_string(), "install".to_string()]),
            None,
            "only the first rpi argument selects a subcommand"
        );
    }

    #[test]
    fn export_bypasses_the_sandbox() {
        assert_eq!(
            maintenance_bypass(&["--export".to_string(), "session.jsonl".to_string()]),
            Some("export")
        );
        assert_eq!(
            maintenance_bypass(&["--export=session.jsonl".to_string()]),
            Some("export")
        );
        assert_eq!(
            maintenance_bypass(&["-p".to_string(), "hi".to_string()]),
            None
        );
    }
}
