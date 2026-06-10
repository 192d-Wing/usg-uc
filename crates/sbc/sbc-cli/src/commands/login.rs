//! Login command implementation.
//!
//! Prompts for credentials, POSTs them to `POST /api/v1/auth/login`, and
//! prints the session token returned by the daemon.

use super::{CommandError, CommandResult};
use crate::api::ApiClient;
use crate::args::{Args, OutputFormat};
use crate::output;
use serde_json::json;
use std::io::{BufRead, Write};

/// Runs the login command.
///
/// Prompts are written to stderr so that stdout carries only the token
/// (or the JSON document in `--json` mode).
///
/// # Errors
///
/// Returns a [`CommandError`] when the daemon cannot be reached, the
/// credentials are rejected, or the response is malformed.
pub fn run(args: &Args) -> CommandResult {
    let stdin = std::io::stdin();
    let mut lines = stdin.lock().lines();
    let username = prompt(&mut lines, "Username: ")?;
    // rpassword is not available in this workspace, so the password is
    // read from stdin and will echo in the terminal.
    eprintln!("note: password input is read from stdin and will echo");
    let password = prompt(&mut lines, "Password: ")?;
    drop(lines);

    let client = ApiClient::from_args(args)?;
    let path = "/api/v1/auth/login";
    let body = json!({ "username": username, "password": password });
    let resp = client.post_json_any_status(path, &body)?;

    if resp.status == 401 {
        return Err(CommandError::new("login failed: invalid credentials"));
    }
    if !resp.is_success() {
        return Err(client.status_error(path, &resp).into());
    }

    let value = resp.json()?;
    let token = value["token"]
        .as_str()
        .ok_or_else(|| CommandError::new("login response did not contain a token"))?;

    match args.format {
        OutputFormat::Json => output::print_json(&value),
        OutputFormat::Text | OutputFormat::Table => {
            println!("{token}");
            eprintln!();
            eprintln!("Login successful. To use the token with subsequent commands:");
            eprintln!("    export SBC_API_TOKEN={token}");
            eprintln!("or pass it explicitly with --token <TOKEN>.");
        }
    }
    Ok(())
}

/// Writes a prompt to stderr and reads one line from stdin.
fn prompt(
    lines: &mut impl Iterator<Item = std::io::Result<String>>,
    label: &str,
) -> Result<String, CommandError> {
    eprint!("{label}");
    let _ = std::io::stderr().flush();
    let line = lines
        .next()
        .transpose()
        .map_err(|e| CommandError::new(format!("failed to read from stdin: {e}")))?
        .ok_or_else(|| CommandError::new("stdin closed before input was provided"))?;
    Ok(line.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prompt_reads_line() {
        let mut lines = vec![Ok("admin".to_string())].into_iter();
        let value = match prompt(&mut lines, "Username: ") {
            Ok(v) => v,
            Err(e) => unreachable!("prompt failed: {e}"),
        };
        assert_eq!(value, "admin");
    }

    #[test]
    fn test_prompt_eof_is_error() {
        let mut lines = std::iter::empty();
        assert!(prompt(&mut lines, "Username: ").is_err());
    }
}
