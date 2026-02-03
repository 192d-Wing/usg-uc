//! Command-line argument parsing.

use std::env;
use std::path::PathBuf;

/// Parsed command-line arguments.
#[derive(Debug, Clone)]
pub struct Args {
    /// Configuration file path.
    pub config_path: Option<PathBuf>,
    /// Verbosity level (0 = normal, 1+ = verbose).
    pub verbose: u8,
    /// Show version and exit.
    pub version: bool,
    /// Show help and exit.
    pub help: bool,
    /// Run in foreground (don't daemonize).
    pub foreground: bool,
    /// PID file path.
    pub pid_file: Option<PathBuf>,
    /// Override listen address.
    pub listen: Option<String>,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            config_path: None,
            verbose: 0,
            version: false,
            help: false,
            foreground: true,
            pid_file: None,
            listen: None,
        }
    }
}

impl Args {
    /// Parses arguments from the command line.
    pub fn parse() -> Self {
        let mut args = Self::default();
        let mut iter = env::args().skip(1);

        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "-c" | "--config" => {
                    if let Some(path) = iter.next() {
                        args.config_path = Some(PathBuf::from(path));
                    }
                }
                "-v" | "--verbose" => {
                    args.verbose = args.verbose.saturating_add(1);
                }
                "-vv" => {
                    args.verbose = args.verbose.saturating_add(2);
                }
                "-vvv" => {
                    args.verbose = args.verbose.saturating_add(3);
                }
                "--version" | "-V" => {
                    args.version = true;
                }
                "--help" | "-h" => {
                    args.help = true;
                }
                "-f" | "--foreground" => {
                    args.foreground = true;
                }
                "-d" | "--daemon" => {
                    args.foreground = false;
                }
                "--pid-file" => {
                    if let Some(path) = iter.next() {
                        args.pid_file = Some(PathBuf::from(path));
                    }
                }
                "-l" | "--listen" => {
                    if let Some(addr) = iter.next() {
                        args.listen = Some(addr);
                    }
                }
                other => {
                    if other.starts_with('-') {
                        eprintln!("Unknown option: {other}");
                    }
                }
            }
        }

        args
    }

    /// Prints help information.
    pub fn print_help() {
        println!(
            r"sbc-daemon - USG Session Border Controller

USAGE:
    sbc-daemon [OPTIONS]

OPTIONS:
    -c, --config <FILE>    Configuration file path (default: /etc/sbc/config.toml)
    -v, --verbose          Increase verbosity (-v, -vv, -vvv)
    -f, --foreground       Run in foreground (default)
    -d, --daemon           Run as daemon
    --pid-file <FILE>      Write PID to file
    -l, --listen <ADDR>    Override listen address
    -V, --version          Print version information
    -h, --help             Print this help message

EXAMPLES:
    sbc-daemon -c /etc/sbc/config.toml
    sbc-daemon -v --foreground
    sbc-daemon -d --pid-file /var/run/sbc.pid

ENVIRONMENT:
    SBC_CONFIG_PATH        Default configuration file path
    SBC_LOG_LEVEL          Logging level (trace, debug, info, warn, error)

SIGNALS:
    SIGTERM, SIGINT        Graceful shutdown
    SIGHUP                 Reload configuration

For more information, see the documentation at https://github.com/usg/usg-uc-sbc"
        );
    }

    /// Returns the effective config path.
    pub fn effective_config_path(&self) -> PathBuf {
        self.config_path
            .clone()
            .or_else(|| env::var("SBC_CONFIG_PATH").ok().map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("/etc/sbc/config.toml"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_args() {
        let args = Args::default();
        assert!(args.config_path.is_none());
        assert_eq!(args.verbose, 0);
        assert!(!args.version);
        assert!(!args.help);
        assert!(args.foreground);
    }

    #[test]
    fn test_effective_config_path() {
        let args = Args::default();
        let path = args.effective_config_path();
        assert_eq!(path, PathBuf::from("/etc/sbc/config.toml"));

        let args = Args {
            config_path: Some(PathBuf::from("/custom/path.toml")),
            ..Default::default()
        };
        assert_eq!(
            args.effective_config_path(),
            PathBuf::from("/custom/path.toml")
        );
    }
}
