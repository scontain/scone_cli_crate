use std::io::Write;

use anyhow::{Context, Result};
use tempfile::NamedTempFile;

/// A temporary file holding session (or config) text for the CLI to read; deleted on drop.
pub(crate) struct SessionFile(NamedTempFile);

impl SessionFile {
    /// Picks `.json` or `.yml` from the content, as the CLI's session reader expects.
    pub(crate) fn create(content: &str) -> Result<Self> {
        let suffix = if content.trim_start().starts_with('{') {
            ".json"
        } else {
            ".yml"
        };
        Self::create_with_suffix(content, suffix)
    }

    pub(crate) fn create_with_suffix(content: &str, suffix: &str) -> Result<Self> {
        let mut file = tempfile::Builder::new()
            .suffix(suffix)
            .tempfile()
            .context("Could not create a temporary file for the SCONE CLI")?;
        file.write_all(content.as_bytes())?;
        file.flush()?;
        Ok(Self(file))
    }

    pub(crate) fn path_str(&self) -> &str {
        self.0.path().to_str().unwrap_or_default()
    }
}
