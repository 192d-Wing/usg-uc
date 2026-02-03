//! Output formatting for CLI.

use crate::args::OutputFormat;
use std::collections::HashMap;

/// Formats output based on the specified format.
pub struct OutputFormatter {
    /// Output format.
    format: OutputFormat,
}

impl OutputFormatter {
    /// Creates a new formatter.
    pub fn new(format: OutputFormat) -> Self {
        Self { format }
    }

    /// Formats a key-value pair.
    pub fn format_kv(&self, key: &str, value: &str) -> String {
        match self.format {
            OutputFormat::Text => format!("{key}: {value}"),
            OutputFormat::Json => format!(r#""{key}": "{value}""#),
            OutputFormat::Table => format!("| {key:<20} | {value:<40} |"),
        }
    }

    /// Formats a map of key-value pairs.
    pub fn format_map(&self, map: &HashMap<String, String>) -> String {
        match self.format {
            OutputFormat::Text => {
                map.iter()
                    .map(|(k, v)| format!("{k}: {v}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            }
            OutputFormat::Json => {
                let pairs: Vec<String> = map
                    .iter()
                    .map(|(k, v)| format!(r#"  "{k}": "{v}""#))
                    .collect();
                format!("{{\n{}\n}}", pairs.join(",\n"))
            }
            OutputFormat::Table => {
                let mut output = String::new();
                output.push_str(&format!(
                    "+{:-<22}+{:-<42}+\n",
                    "", ""
                ));
                output.push_str(&format!(
                    "| {:^20} | {:^40} |\n",
                    "Key", "Value"
                ));
                output.push_str(&format!(
                    "+{:-<22}+{:-<42}+\n",
                    "", ""
                ));
                for (k, v) in map {
                    output.push_str(&format!("| {k:<20} | {v:<40} |\n"));
                }
                output.push_str(&format!(
                    "+{:-<22}+{:-<42}+",
                    "", ""
                ));
                output
            }
        }
    }

    /// Formats a status message.
    pub fn format_status(&self, status: &str, healthy: bool) -> String {
        match self.format {
            OutputFormat::Text => {
                let indicator = if healthy { "✓" } else { "✗" };
                format!("{indicator} {status}")
            }
            OutputFormat::Json => {
                format!(r#"{{"status": "{status}", "healthy": {healthy}}}"#)
            }
            OutputFormat::Table => {
                let indicator = if healthy { "HEALTHY" } else { "UNHEALTHY" };
                format!("| {status:<20} | {indicator:<40} |")
            }
        }
    }

    /// Formats an error message.
    pub fn format_error(&self, message: &str) -> String {
        match self.format {
            OutputFormat::Text => format!("Error: {message}"),
            OutputFormat::Json => format!(r#"{{"error": "{message}"}}"#),
            OutputFormat::Table => format!("| ERROR | {message:<40} |"),
        }
    }

    /// Formats a list of items.
    pub fn format_list<T: std::fmt::Display>(&self, items: &[T]) -> String {
        match self.format {
            OutputFormat::Text => {
                items
                    .iter()
                    .map(|i| format!("  - {i}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            }
            OutputFormat::Json => {
                let json_items: Vec<String> = items.iter().map(|i| format!(r#""{i}""#)).collect();
                format!("[{}]", json_items.join(", "))
            }
            OutputFormat::Table => {
                items
                    .iter()
                    .map(|i| format!("| {i:<62} |"))
                    .collect::<Vec<_>>()
                    .join("\n")
            }
        }
    }
}

/// Helper to print formatted output.
pub fn print_formatted(format: OutputFormat, content: &str) {
    println!("{content}");
    if format == OutputFormat::Json {
        // JSON output gets a trailing newline for cleaner piping
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_kv_text() {
        let formatter = OutputFormatter::new(OutputFormat::Text);
        let output = formatter.format_kv("status", "running");
        assert_eq!(output, "status: running");
    }

    #[test]
    fn test_format_kv_json() {
        let formatter = OutputFormatter::new(OutputFormat::Json);
        let output = formatter.format_kv("status", "running");
        assert_eq!(output, r#""status": "running""#);
    }

    #[test]
    fn test_format_status() {
        let formatter = OutputFormatter::new(OutputFormat::Text);
        let output = formatter.format_status("Database", true);
        assert!(output.contains("✓"));

        let output = formatter.format_status("Cache", false);
        assert!(output.contains("✗"));
    }

    #[test]
    fn test_format_error() {
        let formatter = OutputFormatter::new(OutputFormat::Text);
        let output = formatter.format_error("Connection failed");
        assert!(output.contains("Error:"));

        let formatter = OutputFormatter::new(OutputFormat::Json);
        let output = formatter.format_error("Connection failed");
        assert!(output.contains("error"));
    }

    #[test]
    fn test_format_list() {
        let formatter = OutputFormatter::new(OutputFormat::Text);
        let items = vec!["item1", "item2", "item3"];
        let output = formatter.format_list(&items);
        assert!(output.contains("item1"));
        assert!(output.contains("item2"));
    }

    #[test]
    fn test_format_map() {
        let formatter = OutputFormatter::new(OutputFormat::Text);
        let mut map = HashMap::new();
        map.insert("key1".to_string(), "value1".to_string());
        let output = formatter.format_map(&map);
        assert!(output.contains("key1: value1"));
    }
}
