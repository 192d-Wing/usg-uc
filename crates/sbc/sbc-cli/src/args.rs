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
    /// Daemon gRPC endpoint URL (used by `trunk` subcommands).
    pub grpc_url: String,
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
            grpc_url: "http://localhost:9091".to_string(),
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
    /// Trunk health and registration (requires --features grpc).
    Trunk(TrunkCommand),
    /// Call Detail Records.
    Cdrs(CdrsCommand),
    /// Audit trail tools.
    Audit(AuditCommand),
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

/// Trunk subcommands.
#[derive(Debug, Clone)]
pub enum TrunkCommand {
    /// Show trunk OPTIONS-ping health.
    List,
    /// Show trunk outbound-registration status.
    Registrations,
}

/// Filters shared by `cdrs list` and `cdrs export`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdrsFilter {
    /// Only CDRs set up within this window (`15m`, `1h`, `7d`).
    pub since: Option<String>,
    /// Exact caller.
    pub caller: Option<String>,
    /// Exact callee (dialed or translated).
    pub callee: Option<String>,
    /// Disposition (`answered`, `failed`, ...).
    pub disposition: Option<String>,
    /// Trunk id (final or any attempt).
    pub trunk: Option<String>,
    /// Most records to fetch.
    pub limit: usize,
}

impl Default for CdrsFilter {
    fn default() -> Self {
        Self {
            since: None,
            caller: None,
            callee: None,
            disposition: None,
            trunk: None,
            limit: 100,
        }
    }
}

/// `cdrs` subcommands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CdrsCommand {
    /// List recent CDRs from the daemon's ring.
    List { filter: CdrsFilter },
    /// Show one CDR.
    Show { record_id: String },
    /// Export recent CDRs as `jsonl` or `csv` to stdout.
    Export { filter: CdrsFilter, format: String },
    /// Verify CDR files offline (hash chain, sidecar digest).
    Verify { files: Vec<String> },
}

/// `audit` subcommands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditCommand {
    /// Verify uc-audit files offline (hash chain, sequence continuity).
    /// `require_anchor` fails when the first file does not start at
    /// sequence 0 (its head may have been deleted).
    Verify {
        files: Vec<String>,
        require_anchor: bool,
    },
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
        let mut args = Self::default();
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
                "--grpc-url" => {
                    iter.next();
                    if let Some(url) = iter.next() {
                        args.grpc_url = url;
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
                "trunk" => Self::parse_trunk_command(&mut iter),
                "cdrs" => Self::parse_cdrs_command(&mut iter, &mut args),
                "audit" => Self::parse_audit_command(&mut iter),
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

        // Scan remaining args for global flags that appeared after the
        // subcommand (e.g. `sbc-cli status --json`).  Without this second
        // pass, trailing flags like --json / --verbose / --api-url were
        // silently ignored.
        for arg in iter {
            match arg.as_str() {
                "-h" | "--help" => args.help = true,
                "-V" | "--version" => args.version = true,
                "-v" | "--verbose" => args.verbose = args.verbose.saturating_add(1),
                "--json" => args.format = OutputFormat::Json,
                "--table" => args.format = OutputFormat::Table,
                // --api-url and --grpc-url require a value; we cannot
                // easily peek ahead in a for-loop, so these are
                // intentionally handled only in the leading-flags pass.
                // Users who place them after the subcommand will see an
                // "unknown argument" warning.
                other => {
                    eprintln!("Warning: unrecognized trailing argument: {other}");
                }
            }
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

    /// Parses trunk subcommand.
    fn parse_trunk_command(iter: &mut impl Iterator<Item = String>) -> Command {
        match iter.next().as_deref() {
            Some("list") | None => Command::Trunk(TrunkCommand::List),
            Some("registrations") => Command::Trunk(TrunkCommand::Registrations),
            Some(other) => {
                eprintln!("Unknown trunk subcommand: {other}");
                Command::Trunk(TrunkCommand::List)
            }
        }
    }

    /// Parses `cdrs` subcommand options. Global output flags (`--json`,
    /// `--table`, `-v`) may appear among them.
    fn parse_cdrs_command(iter: &mut impl Iterator<Item = String>, args: &mut Self) -> Command {
        let sub = iter.next();
        let mut filter = CdrsFilter::default();
        let mut format = "jsonl".to_string();
        let mut positional = Vec::new();
        while let Some(a) = iter.next() {
            match a.as_str() {
                "--since" => filter.since = iter.next(),
                "--caller" => filter.caller = iter.next(),
                "--callee" => filter.callee = iter.next(),
                "--disposition" => filter.disposition = iter.next(),
                "--trunk" => filter.trunk = iter.next(),
                "--limit" => {
                    let v = iter.next().unwrap_or_default();
                    match v.parse::<usize>() {
                        Ok(n) if n > 0 => filter.limit = n.min(200_000),
                        _ => eprintln!("Warning: invalid --limit {v:?}; using {}", filter.limit),
                    }
                }
                "--format" => format = iter.next().unwrap_or_default(),
                "--json" => args.format = OutputFormat::Json,
                "--table" => args.format = OutputFormat::Table,
                "-v" | "--verbose" => args.verbose = args.verbose.saturating_add(1),
                other if other.starts_with("--") => {
                    eprintln!("Warning: unrecognized cdrs option: {other}");
                }
                _ => positional.push(a),
            }
        }
        let cmd = match sub.as_deref() {
            Some("list") | None => CdrsCommand::List { filter },
            Some("show") => CdrsCommand::Show {
                record_id: positional.into_iter().next().unwrap_or_default(),
            },
            Some("export") => {
                if format != "jsonl" && format != "csv" {
                    eprintln!("Warning: unknown --format {format:?}; using jsonl");
                    format = "jsonl".to_string();
                }
                CdrsCommand::Export { filter, format }
            }
            Some("verify") => CdrsCommand::Verify { files: positional },
            Some(other) => {
                eprintln!("Unknown cdrs subcommand: {other}");
                CdrsCommand::List { filter }
            }
        };
        Command::Cdrs(cmd)
    }

    /// Parses `audit` subcommand. Every remaining argument is a file,
    /// except `--require-anchor`.
    fn parse_audit_command(iter: &mut impl Iterator<Item = String>) -> Command {
        match iter.next().as_deref() {
            Some("verify") => {
                let mut require_anchor = false;
                let files = iter
                    .filter(|a| {
                        let flag = a == "--require-anchor";
                        require_anchor |= flag;
                        !flag
                    })
                    .collect();
                Command::Audit(AuditCommand::Verify {
                    files,
                    require_anchor,
                })
            }
            Some(other) => {
                eprintln!("Unknown audit subcommand: {other}");
                Command::Help
            }
            None => Command::Help,
        }
    }

    /// Prints help information.
    pub fn print_help() {
        println!(
            r"sbc-cli - USG Session Border Controller CLI

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
    trunk               Trunk health and registration (requires --features grpc)
        list            Show OPTIONS-ping health for every trunk
        registrations   Show outbound-registration status for every trunk
    cdrs                Call Detail Records
        list [FILTERS]  List recent CDRs (requires --features grpc)
        show <ID>       Show one CDR as JSON (requires --features grpc)
        export [FILTERS] [--format jsonl|csv]
                        Write recent CDRs to stdout (requires --features grpc)
        verify <FILE>.. Verify CDR files offline (hash chain, .sha384 sidecar)
        FILTERS: --since 1h --caller X --callee X --disposition D
                 --trunk T --limit N
    audit               Audit trail
        verify [--require-anchor] <FILE>..
                        Verify audit files offline (hash chain, sequence)
    health              Perform health check
    metrics             Show Prometheus metrics
    version             Show version information
    help                Print this help message

OPTIONS:
    -h, --help              Print help information
    -V, --version           Print version information
    -v, --verbose           Increase verbosity
    --json                  Output in JSON format
    --table                 Output in table format
    --api-url <URL>         API endpoint URL (default: http://localhost:8080)
    --grpc-url <URL>        Daemon gRPC URL for trunk subcommands (default: http://localhost:9091)

EXAMPLES:
    sbc-cli status
    sbc-cli config show --json
    sbc-cli calls list
    sbc-cli calls terminate abc123
    sbc-cli health
    sbc-cli metrics
    sbc-cli trunk list
    sbc-cli cdrs list --since 1h --disposition failed
    sbc-cli cdrs export --format csv > cdrs.csv
    sbc-cli cdrs verify /var/lib/usg-sbc/cdr/*.jsonl
    sbc-cli audit verify /var/log/sbc/audit.log
    sbc-cli --grpc-url http://sbc-daemon:9091 trunk registrations

For more information, see the documentation at https://github.com/usg/usg-uc-sbc"
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
    fn cdrs_command_parses_filters_and_files() {
        let mut args = Args::default();
        let it = [
            "export", "--since", "1h", "--caller", "alice", "--format", "csv", "--json",
        ]
        .map(String::from);
        let cmd = Args::parse_cdrs_command(&mut it.into_iter(), &mut args);
        let expected = CdrsFilter {
            since: Some("1h".to_string()),
            caller: Some("alice".to_string()),
            ..CdrsFilter::default()
        };
        assert!(
            matches!(&cmd, Command::Cdrs(CdrsCommand::Export { filter, format })
                if format == "csv" && *filter == expected),
            "{cmd:?}"
        );
        assert_eq!(args.format, OutputFormat::Json);

        let it = ["verify", "a.jsonl", "b.jsonl"].map(String::from);
        let cmd = Args::parse_cdrs_command(&mut it.into_iter(), &mut args);
        assert_eq!(
            cmd_files(cmd),
            vec!["a.jsonl".to_string(), "b.jsonl".to_string()]
        );
    }

    #[test]
    fn audit_verify_parses_files() {
        let it = ["verify", "a.log", "b.log"].map(String::from);
        let cmd = Args::parse_audit_command(&mut it.into_iter());
        assert!(
            matches!(&cmd, Command::Audit(AuditCommand::Verify { files, require_anchor: false })
                if files == &["a.log".to_string(), "b.log".to_string()]),
            "{cmd:?}"
        );
        let it = ["verify", "--require-anchor", "a.log"].map(String::from);
        let cmd = Args::parse_audit_command(&mut it.into_iter());
        assert!(
            matches!(&cmd, Command::Audit(AuditCommand::Verify { files, require_anchor: true })
                if files == &["a.log".to_string()]),
            "{cmd:?}"
        );
        let it = ["bogus"].map(String::from);
        assert!(matches!(
            Args::parse_audit_command(&mut it.into_iter()),
            Command::Help
        ));
    }

    fn cmd_files(cmd: Command) -> Vec<String> {
        match cmd {
            Command::Cdrs(CdrsCommand::Verify { files }) => files,
            _ => Vec::new(),
        }
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
