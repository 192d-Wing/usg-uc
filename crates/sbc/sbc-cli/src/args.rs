//! Command-line argument parsing for SBC CLI.

use std::env;

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
            api_url: "http://localhost:8080".to_string(),
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
    Validate { path: Option<String> },
    /// Reload configuration.
    Reload,
}

/// Calls subcommands.
#[derive(Debug, Clone)]
pub enum CallsCommand {
    /// List active calls.
    List,
    /// Show call details.
    Show { call_id: String },
    /// Terminate a call.
    Terminate { call_id: String },
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
    pub fn parse() -> Self {
        let mut args = Args::default();
        let mut iter = env::args().skip(1).peekable();

        // Parse global flags first
        while let Some(arg) = iter.peek() {
            match arg.as_str() {
                "-h" | "--help" => {
                    args.help = true;
                    iter.next();
                }
                "-V" | "--version" => {
                    args.version = true;
                    iter.next();
                }
                "-v" | "--verbose" => {
                    args.verbose = args.verbose.saturating_add(1);
                    iter.next();
                }
                "--json" => {
                    args.format = OutputFormat::Json;
                    iter.next();
                }
                "--table" => {
                    args.format = OutputFormat::Table;
                    iter.next();
                }
                "--api-url" => {
                    iter.next();
                    if let Some(url) = iter.next() {
                        args.api_url = url;
                    }
                }
                _ => break,
            }
        }

        // Parse command
        if let Some(cmd) = iter.next() {
            args.command = match cmd.as_str() {
                "status" => Command::Status,
                "config" => Self::parse_config_command(&mut iter),
                "calls" => Self::parse_calls_command(&mut iter),
                "health" => Command::Health,
                "metrics" => Command::Metrics,
                "version" => Command::Version,
                "help" => Command::Help,
                _ => {
                    eprintln!("Unknown command: {cmd}");
                    Command::Help
                }
            };
        }

        args
    }

    /// Parses config subcommand.
    fn parse_config_command(iter: &mut impl Iterator<Item = String>) -> Command {
        match iter.next().as_deref() {
            Some("show") | None => Command::Config(ConfigCommand::Show),
            Some("validate") => Command::Config(ConfigCommand::Validate { path: iter.next() }),
            Some("reload") => Command::Config(ConfigCommand::Reload),
            Some(other) => {
                eprintln!("Unknown config subcommand: {other}");
                Command::Config(ConfigCommand::Show)
            }
        }
    }

    /// Parses calls subcommand.
    fn parse_calls_command(iter: &mut impl Iterator<Item = String>) -> Command {
        match iter.next().as_deref() {
            Some("list") | None => Command::Calls(CallsCommand::List),
            Some("show") => Command::Calls(CallsCommand::Show {
                call_id: iter.next().unwrap_or_default(),
            }),
            Some("terminate") => Command::Calls(CallsCommand::Terminate {
                call_id: iter.next().unwrap_or_default(),
            }),
            Some("stats") => Command::Calls(CallsCommand::Stats),
            Some(other) => {
                eprintln!("Unknown calls subcommand: {other}");
                Command::Calls(CallsCommand::List)
            }
        }
    }

    /// Prints help information.
    pub fn print_help() {
        println!(
            r#"sbc-cli - USG Session Border Controller CLI

USAGE:
    sbc-cli [OPTIONS] <COMMAND>

COMMANDS:
    status              Show SBC status and statistics
    config              Configuration management
        show            Show current configuration
        validate [PATH] Validate configuration file
        reload          Reload configuration
    calls               Call management
        list            List active calls
        show <ID>       Show call details
        terminate <ID>  Terminate a call
        stats           Show call statistics
    health              Perform health check
    metrics             Show Prometheus metrics
    version             Show version information
    help                Print this help message

OPTIONS:
    -h, --help          Print help information
    -V, --version       Print version information
    -v, --verbose       Increase verbosity
    --json              Output in JSON format
    --table             Output in table format
    --api-url <URL>     API endpoint URL (default: http://localhost:8080)

EXAMPLES:
    sbc-cli status
    sbc-cli config show --json
    sbc-cli calls list
    sbc-cli calls terminate abc123
    sbc-cli health
    sbc-cli metrics

For more information, see the documentation at https://github.com/usg/usg-uc-sbc"#
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_args() {
        let args = Args::default();
        assert!(matches!(args.command, Command::None));
        assert!(!args.help);
        assert!(!args.version);
        assert_eq!(args.format, OutputFormat::Text);
    }

    #[test]
    fn test_output_format() {
        assert_eq!(OutputFormat::Text, OutputFormat::Text);
        assert_ne!(OutputFormat::Text, OutputFormat::Json);
    }

    #[test]
    fn test_config_command() {
        assert!(matches!(ConfigCommand::Show, ConfigCommand::Show));
    }

    #[test]
    fn test_calls_command() {
        let cmd = CallsCommand::Show {
            call_id: "abc".to_string(),
        };
        if let CallsCommand::Show { call_id } = cmd {
            assert_eq!(call_id, "abc");
        }
    }
}
