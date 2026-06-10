//! Command-line argument parsing for SBC CLI.
//!
//! Parsing is strict: unknown options, unknown (sub)commands, missing
//! option values, and stray positional arguments are all reported as
//! [`ParseError`]s, which the caller turns into a usage message on
//! stderr and exit code 2.

use std::env;

/// Error produced when command-line arguments cannot be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// Human-readable description of the problem.
    pub message: String,
}

impl ParseError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ParseError {}

/// Parsed command-line arguments.
#[derive(Debug, Clone)]
pub struct Args {
    /// Command to execute.
    pub command: Command,
    /// Show help.
    pub help: bool,
    /// Show version.
    pub version: bool,
    /// Output format.
    pub format: OutputFormat,
    /// API endpoint URL.
    pub api_url: String,
    /// Path to a PEM CA certificate used to verify the daemon's TLS cert.
    pub ca_cert: Option<String>,
    /// Skip TLS certificate verification (dangerous).
    pub insecure: bool,
    /// Bearer token for API authentication (`--token` or `SBC_API_TOKEN`).
    pub token: Option<String>,
    /// Verbosity level.
    pub verbose: u8,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            command: Command::None,
            help: false,
            version: false,
            format: OutputFormat::Text,
            api_url: "https://localhost:8443".to_string(),
            ca_cert: None,
            insecure: false,
            token: None,
            verbose: 0,
        }
    }
}

/// Command to execute.
#[derive(Debug, Clone)]
pub enum Command {
    /// Show SBC status.
    Status,
    /// Configuration management.
    Config(ConfigCommand),
    /// Call management.
    Calls(CallsCommand),
    /// Health check.
    Health,
    /// Show metrics.
    Metrics,
    /// Authenticate against the daemon API and obtain a token.
    Login,
    /// Show version.
    Version,
    /// Show help.
    Help,
    /// No command specified.
    None,
}

/// Configuration subcommands.
#[derive(Debug, Clone)]
pub enum ConfigCommand {
    /// Show current configuration.
    Show,
    /// Validate configuration file.
    Validate {
        /// Path to the configuration file.
        path: Option<String>,
    },
    /// Reload configuration.
    Reload,
}

/// Calls subcommands.
#[derive(Debug, Clone)]
pub enum CallsCommand {
    /// List active calls.
    List,
    /// Show call details.
    Show {
        /// Identifier of the call to display.
        call_id: String,
    },
    /// Terminate a call.
    Terminate {
        /// Identifier of the call to terminate.
        call_id: String,
    },
    /// Show call statistics.
    Stats,
}

/// Output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Plain text output.
    Text,
    /// JSON output.
    Json,
    /// Table output.
    Table,
}

impl Args {
    /// Parses arguments from the command line.
    ///
    /// # Errors
    ///
    /// Returns a [`ParseError`] for unknown options, unknown commands or
    /// subcommands, missing option values, or unexpected extra arguments.
    pub fn parse() -> Result<Self, ParseError> {
        Self::parse_from(env::args().skip(1))
    }

    /// Parses arguments from an explicit iterator (excluding `argv[0]`).
    ///
    /// Options may appear before or after the command; they are consumed
    /// wherever they occur.
    ///
    /// # Errors
    ///
    /// Returns a [`ParseError`] for unknown options, unknown commands or
    /// subcommands, missing option values, or unexpected extra arguments.
    pub fn parse_from<I>(raw: I) -> Result<Self, ParseError>
    where
        I: IntoIterator<Item = String>,
    {
        let mut args = Self::default();
        let mut positionals: Vec<String> = Vec::new();
        let mut iter = raw.into_iter();

        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "-h" | "--help" => args.help = true,
                "-V" | "--version" => args.version = true,
                "-v" | "--verbose" => args.verbose = args.verbose.saturating_add(1),
                "--json" => args.format = OutputFormat::Json,
                "--table" => args.format = OutputFormat::Table,
                "--insecure" => args.insecure = true,
                "--api-url" => args.api_url = Self::require_value(&mut iter, "--api-url")?,
                "--ca-cert" => args.ca_cert = Some(Self::require_value(&mut iter, "--ca-cert")?),
                "--token" => args.token = Some(Self::require_value(&mut iter, "--token")?),
                other if other.starts_with('-') => {
                    return Err(ParseError::new(format!("unknown option '{other}'")));
                }
                _ => positionals.push(arg),
            }
        }

        args.command = Self::parse_command(&positionals)?;
        Ok(args)
    }

    /// Pulls the value for an option that requires one.
    fn require_value(
        iter: &mut impl Iterator<Item = String>,
        option: &str,
    ) -> Result<String, ParseError> {
        iter.next()
            .ok_or_else(|| ParseError::new(format!("option '{option}' requires a value")))
    }

    /// Parses the positional arguments into a command.
    fn parse_command(positionals: &[String]) -> Result<Command, ParseError> {
        let Some((cmd, rest)) = positionals.split_first() else {
            return Ok(Command::None);
        };

        let command = match cmd.as_str() {
            "status" => Self::expect_no_extra(rest, "status", Command::Status)?,
            "config" => Self::parse_config_command(rest)?,
            "calls" => Self::parse_calls_command(rest)?,
            "health" => Self::expect_no_extra(rest, "health", Command::Health)?,
            "metrics" => Self::expect_no_extra(rest, "metrics", Command::Metrics)?,
            "login" => Self::expect_no_extra(rest, "login", Command::Login)?,
            "version" => Self::expect_no_extra(rest, "version", Command::Version)?,
            "help" => Self::expect_no_extra(rest, "help", Command::Help)?,
            other => return Err(ParseError::new(format!("unknown command '{other}'"))),
        };
        Ok(command)
    }

    /// Rejects stray positional arguments after a complete command.
    fn expect_no_extra(
        rest: &[String],
        context: &str,
        command: Command,
    ) -> Result<Command, ParseError> {
        if let Some(extra) = rest.first() {
            return Err(ParseError::new(format!(
                "unexpected argument '{extra}' after '{context}'"
            )));
        }
        Ok(command)
    }

    /// Parses config subcommand.
    fn parse_config_command(rest: &[String]) -> Result<Command, ParseError> {
        let Some((sub, rest)) = rest.split_first() else {
            return Err(ParseError::new(
                "'config' requires a subcommand (show, validate, reload)",
            ));
        };
        match sub.as_str() {
            "show" => Self::expect_no_extra(rest, "config show", Command::Config(ConfigCommand::Show)),
            "validate" => {
                let path = rest.first().cloned();
                Self::expect_no_extra(
                    rest.get(1..).unwrap_or_default(),
                    "config validate",
                    Command::Config(ConfigCommand::Validate { path }),
                )
            }
            "reload" => {
                Self::expect_no_extra(rest, "config reload", Command::Config(ConfigCommand::Reload))
            }
            other => Err(ParseError::new(format!(
                "unknown config subcommand '{other}'"
            ))),
        }
    }

    /// Parses calls subcommand.
    fn parse_calls_command(rest: &[String]) -> Result<Command, ParseError> {
        let Some((sub, rest)) = rest.split_first() else {
            return Err(ParseError::new(
                "'calls' requires a subcommand (list, show, terminate, stats)",
            ));
        };
        match sub.as_str() {
            "list" => Self::expect_no_extra(rest, "calls list", Command::Calls(CallsCommand::List)),
            "show" => {
                let call_id = rest
                    .first()
                    .cloned()
                    .ok_or_else(|| ParseError::new("'calls show' requires a <CALL_ID> argument"))?;
                Self::expect_no_extra(
                    rest.get(1..).unwrap_or_default(),
                    "calls show",
                    Command::Calls(CallsCommand::Show { call_id }),
                )
            }
            "terminate" => {
                let call_id = rest.first().cloned().ok_or_else(|| {
                    ParseError::new("'calls terminate' requires a <CALL_ID> argument")
                })?;
                Self::expect_no_extra(
                    rest.get(1..).unwrap_or_default(),
                    "calls terminate",
                    Command::Calls(CallsCommand::Terminate { call_id }),
                )
            }
            "stats" => {
                Self::expect_no_extra(rest, "calls stats", Command::Calls(CallsCommand::Stats))
            }
            other => Err(ParseError::new(format!(
                "unknown calls subcommand '{other}'"
            ))),
        }
    }

    /// Returns the usage/help text.
    pub const fn help_text() -> &'static str {
        r"sbc-cli - USG Session Border Controller CLI

USAGE:
    sbc-cli [OPTIONS] <COMMAND>

COMMANDS:
    status              Show SBC status and statistics
    config              Configuration management
        show            Show current configuration (daemon API)
        validate [PATH] Validate a local configuration file
        reload          Reload configuration (daemon API)
    calls               Call management
        list            List active calls
        show <ID>       Show call details
        terminate <ID>  Terminate a call
        stats           Show call statistics
    health              Query daemon health
    metrics             Show daemon Prometheus metrics
    login               Authenticate and obtain an API token
    version             Show version information
    help                Print this help message

OPTIONS:
    -h, --help          Print help information
    -V, --version       Print version information
    -v, --verbose       Increase verbosity
    --json              Output in JSON format
    --table             Output in table format
    --api-url <URL>     API endpoint URL (default: https://localhost:8443)
    --ca-cert <PATH>    PEM CA certificate to verify the daemon's TLS cert
    --insecure          Skip TLS certificate verification (NOT recommended)
    --token <TOKEN>     Bearer token (or set SBC_API_TOKEN)

EXAMPLES:
    sbc-cli login
    sbc-cli --token $SBC_API_TOKEN status
    sbc-cli --ca-cert /etc/sbc/certs/api.pem calls list
    sbc-cli config validate /etc/sbc/config.toml
    sbc-cli health --json

For more information, see the documentation at https://github.com/usg/usg-uc-sbc"
    }

    /// Prints help information to stdout.
    pub fn print_help() {
        println!("{}", Self::help_text());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Args, ParseError> {
        Args::parse_from(args.iter().map(ToString::to_string))
    }

    #[test]
    fn test_default_args() {
        let args = Args::default();
        assert!(matches!(args.command, Command::None));
        assert!(!args.help);
        assert!(!args.version);
        assert!(!args.insecure);
        assert!(args.token.is_none());
        assert!(args.ca_cert.is_none());
        assert_eq!(args.format, OutputFormat::Text);
        assert_eq!(args.api_url, "https://localhost:8443");
    }

    #[test]
    fn test_parse_simple_commands() {
        assert!(matches!(parse(&["status"]).unwrap().command, Command::Status));
        assert!(matches!(parse(&["health"]).unwrap().command, Command::Health));
        assert!(matches!(parse(&["metrics"]).unwrap().command, Command::Metrics));
        assert!(matches!(parse(&["login"]).unwrap().command, Command::Login));
        assert!(matches!(parse(&["version"]).unwrap().command, Command::Version));
        assert!(matches!(parse(&["help"]).unwrap().command, Command::Help));
        assert!(matches!(parse(&[]).unwrap().command, Command::None));
    }

    #[test]
    fn test_unknown_command_is_error() {
        let err = parse(&["bogus"]).unwrap_err();
        assert!(err.message.contains("unknown command"));
    }

    #[test]
    fn test_unknown_subcommand_is_error() {
        assert!(parse(&["config", "frobnicate"]).is_err());
        assert!(parse(&["calls", "frobnicate"]).is_err());
    }

    #[test]
    fn test_missing_subcommand_is_error() {
        assert!(parse(&["config"]).is_err());
        assert!(parse(&["calls"]).is_err());
    }

    #[test]
    fn test_unknown_flag_is_error() {
        let err = parse(&["status", "--frobnicate"]).unwrap_err();
        assert!(err.message.contains("unknown option"));
    }

    #[test]
    fn test_flags_after_command_are_consumed() {
        let args = parse(&["status", "--json"]).unwrap();
        assert!(matches!(args.command, Command::Status));
        assert_eq!(args.format, OutputFormat::Json);

        let args = parse(&["calls", "list", "--api-url", "https://sbc:9443"]).unwrap();
        assert!(matches!(args.command, Command::Calls(CallsCommand::List)));
        assert_eq!(args.api_url, "https://sbc:9443");
    }

    #[test]
    fn test_extra_positional_is_error() {
        assert!(parse(&["status", "extra"]).is_err());
        assert!(parse(&["calls", "list", "extra"]).is_err());
        assert!(parse(&["calls", "show", "abc", "extra"]).is_err());
    }

    #[test]
    fn test_option_missing_value_is_error() {
        assert!(parse(&["--api-url"]).is_err());
        assert!(parse(&["--ca-cert"]).is_err());
        assert!(parse(&["--token"]).is_err());
    }

    #[test]
    fn test_tls_and_auth_flags() {
        let args = parse(&[
            "--insecure",
            "--ca-cert",
            "/tmp/ca.pem",
            "--token",
            "abc123",
            "status",
        ])
        .unwrap();
        assert!(args.insecure);
        assert_eq!(args.ca_cert.as_deref(), Some("/tmp/ca.pem"));
        assert_eq!(args.token.as_deref(), Some("abc123"));
    }

    #[test]
    fn test_calls_show_requires_id() {
        assert!(parse(&["calls", "show"]).is_err());
        let args = parse(&["calls", "show", "abc"]).unwrap();
        if let Command::Calls(CallsCommand::Show { call_id }) = args.command {
            assert_eq!(call_id, "abc");
        } else {
            panic!("expected calls show");
        }
    }

    #[test]
    fn test_calls_terminate_requires_id() {
        assert!(parse(&["calls", "terminate"]).is_err());
        let args = parse(&["calls", "terminate", "abc"]).unwrap();
        assert!(matches!(
            args.command,
            Command::Calls(CallsCommand::Terminate { .. })
        ));
    }

    #[test]
    fn test_config_validate_path() {
        let args = parse(&["config", "validate", "/etc/sbc/config.toml"]).unwrap();
        if let Command::Config(ConfigCommand::Validate { path }) = args.command {
            assert_eq!(path.as_deref(), Some("/etc/sbc/config.toml"));
        } else {
            panic!("expected config validate");
        }
    }

    #[test]
    fn test_output_format() {
        assert_eq!(OutputFormat::Text, OutputFormat::Text);
        assert_ne!(OutputFormat::Text, OutputFormat::Json);
    }
}
