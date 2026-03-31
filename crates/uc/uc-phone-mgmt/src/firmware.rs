//! Firmware management for phone devices.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Metadata about an available firmware image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareInfo {
    /// Model family this firmware applies to (e.g. "polycom_vvx").
    pub model_family: String,
    /// Firmware version string.
    pub version: String,
    /// Filename of the firmware image.
    pub filename: String,
    /// Size of the firmware image in bytes.
    pub size_bytes: u64,
    /// SHA-256 checksum hex string.
    pub sha256: String,
    /// Release date (ISO 8601).
    pub release_date: String,
}

/// Manages firmware images stored on the local filesystem.
pub struct FirmwareManager {
    firmware_dir: PathBuf,
}

impl FirmwareManager {
    /// Create a new firmware manager rooted at the given directory.
    #[must_use]
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            firmware_dir: dir.into(),
        }
    }

    /// List available firmware images for a given model family.
    ///
    /// Scans `<firmware_dir>/<model_family>/` for firmware metadata files.
    /// Returns an empty vec if the directory does not exist.
    #[must_use]
    pub fn list_available(&self, model_family: &str) -> Vec<FirmwareInfo> {
        let family_dir = self.firmware_dir.join(model_family);
        let Ok(entries) = std::fs::read_dir(&family_dir) else {
            return Vec::new();
        };

        let mut results = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                if let Ok(contents) = std::fs::read_to_string(&path) {
                    if let Ok(info) = serde_json::from_str::<FirmwareInfo>(&contents) {
                        results.push(info);
                    }
                }
            }
        }
        results
    }

    /// Get the filesystem path for a specific firmware version.
    ///
    /// Returns `None` if the firmware file does not exist.
    #[must_use]
    pub fn get_firmware_path(&self, model_family: &str, version: &str) -> Option<PathBuf> {
        let path = self.firmware_dir.join(model_family).join(version);
        if path.exists() {
            Some(path)
        } else {
            None
        }
    }

    /// Determine if a firmware upgrade is needed by comparing version strings.
    ///
    /// Uses simple lexicographic comparison; returns `true` if target > current.
    #[must_use]
    pub fn needs_upgrade(&self, current: &str, target: &str) -> bool {
        target > current
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_needs_upgrade() {
        let mgr = FirmwareManager::new("/tmp/fw");
        assert!(mgr.needs_upgrade("1.0.0", "2.0.0"));
        assert!(!mgr.needs_upgrade("2.0.0", "1.0.0"));
        assert!(!mgr.needs_upgrade("1.0.0", "1.0.0"));
    }

    #[test]
    fn test_list_available_nonexistent_dir() {
        let mgr = FirmwareManager::new("/nonexistent/firmware/dir");
        let result = mgr.list_available("polycom_vvx");
        assert!(result.is_empty());
    }

    #[test]
    fn test_get_firmware_path_nonexistent() {
        let mgr = FirmwareManager::new("/nonexistent/firmware/dir");
        assert!(mgr.get_firmware_path("polycom_vvx", "1.0.0").is_none());
    }
}
