use std::path::Path;

use anyhow::bail;

use crate::engine::{SconeCliCommandResult, execute_scone_cli};

/// Runs `scone <args>`, pointing it at one config file when there is one.
pub(crate) struct Runner<'a> {
    config: Option<&'a Path>,
}

impl<'a> Runner<'a> {
    pub(crate) fn new(config: Option<&'a Path>) -> Self {
        Self { config }
    }

    /// Runs the command and returns its result whatever the exit code.
    pub(crate) fn raw(&self, args: &[String]) -> SconeCliCommandResult {
        let env: Vec<(String, String)> = self
            .config
            .map(|path| {
                (
                    "SCONE_CLI_CONFIG".to_owned(),
                    path.to_string_lossy().into_owned(),
                )
            })
            .into_iter()
            .collect();
        execute_scone_cli(args, env, vec!["SCONE_CONFIG_ID"])
    }

    /// Runs the command and returns stdout, turning a non-zero exit code into an error.
    pub(crate) fn run(&self, args: &[String], error_code: &str) -> anyhow::Result<String> {
        let SconeCliCommandResult {
            exit_code,
            stdout,
            stderr,
        } = self.raw(args);
        if exit_code != 0 {
            bail!(
                "Scone CLI command failed with exit code {exit_code} (ERROR {error_code}): {stderr}"
            );
        }
        Ok(stdout)
    }
}
