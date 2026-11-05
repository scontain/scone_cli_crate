use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use scone_cli_api::{
    AuditLogRequest, CasAddress, CasAttestRequest, CasIdentityKeysHash, CasProvisionRequest,
    CheckpointsRequest, CommandOutput, SconeCliApi, SessionEncryptionKeySource,
};

use crate::{commands, report, runner::Runner, session_file::CliTempFile, version_gate};

/// Runs SCONE CLI operations against one config file by executing the `scone` binary.
#[derive(Clone, Debug, Default)]
pub struct SconeCli {
    config: Option<PathBuf>,
    workdir: Option<PathBuf>,
}

/// This crate [`SconeCli::new()`] uses this ENV to find the workdir for temporary files.
const SCONE_CLI_WORKDIR_ENV: &str = "SCONE_CLI_WORKDIR";

impl SconeCli {
    #[must_use]
    // This underlying `scone` binary resolves the default config through the `SCONE_CLI_CONFIG` ENV or uses $HOME/.cas/config.json.
    // This also tries to resolve the workdir specified by `SCONE_CLI_WORKDIR` ENV, or defaults to the system's temp directory.
    pub fn new() -> Self {
        let workdir = std::env::var_os(SCONE_CLI_WORKDIR_ENV).map(PathBuf::from);
        Self {
            config: None,
            workdir,
        }
    }

    /// Specifies a config file to use for the underlying `scone` binary.
    /// This overwrites the `SCONE_CLI_CONFIG` ENV  with the specified path.
    pub fn with_config(mut self, config_path: impl Into<PathBuf>) -> Self {
        self.config = Some(config_path.into());
        self
    }

    /// Specifies a workdir for temporary files used by the underlying `scone` binary.
    /// This overwrites the `SCONE_CLI_WORKDIR` ENV with the specified path
    pub fn with_workdir(mut self, workdir: impl Into<PathBuf>) -> Self {
        self.workdir = Some(workdir.into());
        self
    }

    fn runner(&self) -> Runner<'_> {
        Runner::new(self.config.as_deref())
    }

    /// Applies version gating, runs `scone <args>` and returns stdout.
    fn run_gated(&self, args: Vec<String>, error_code: &str) -> Result<String> {
        let args = version_gate::filter_for_installed_cli(&self.runner(), args)?;
        self.runner().run(&args, error_code)
    }

    fn upload_session(
        &self,
        verb: &str,
        cas: &CasAddress,
        yaml: &str,
        sign: bool,
        error_code: &str,
    ) -> Result<String> {
        let body = if sign {
            self.sign_session(yaml)?
        } else {
            yaml.to_owned()
        };
        let file = CliTempFile::create(&body, self.workdir.as_deref())?;
        let args = commands::session_upload_args(verb, cas, file.path_str());
        self.runner().run(&args, error_code)?;
        // The CLI reports success; the hash is that of the session as uploaded.
        self.session_hash(&body)
    }
}

impl SconeCliApi for SconeCli {
    fn config_path(&self) -> Option<&Path> {
        self.config.as_deref()
    }

    fn key_hash(&self) -> Result<String> {
        let args = strings(&["self", "show-key-hash"]);
        Ok(self
            .runner()
            .run(&args, "50011-2231-9081")?
            .trim()
            .to_owned())
    }

    fn session_signing_public_key(&self) -> Result<String> {
        let args = strings(&["self", "show-session-signing-key"]);
        Ok(self.runner().run(&args, "9808-322-4776")?.trim().to_owned())
    }

    fn validate_session(&self, yaml: &str) -> Result<()> {
        let file = CliTempFile::create(yaml, self.workdir.as_deref())?;
        let args = strings(&["session", "check", file.path_str()]);
        self.runner().run(&args, "50012-4417-1290").map(|_| ())
    }

    fn session_hash(&self, yaml: &str) -> Result<String> {
        let file = CliTempFile::create(yaml, self.workdir.as_deref())?;
        let args = strings(&["session", "calculate-hash", file.path_str()]);
        Ok(self
            .runner()
            .run(&args, "19175-9146-3013")?
            .trim()
            .to_owned())
    }

    fn sign_session(&self, yaml: &str) -> Result<String> {
        let file = CliTempFile::create(yaml, self.workdir.as_deref())?;
        let args = strings(&["session", "sign", file.path_str()]);
        Ok(self
            .runner()
            .run(&args, "28666-19528-6399")?
            .trim()
            .to_owned())
    }

    fn encrypt_session(
        &self,
        yaml: &str,
        key_source: SessionEncryptionKeySource,
    ) -> Result<String> {
        let file = CliTempFile::create(yaml, self.workdir.as_deref())?;
        let mut args = strings(&["session", "encrypt", file.path_str()]);
        match key_source {
            SessionEncryptionKeySource::CasAddress(cas) => {
                args.extend(strings(&["--cas", &cas]));
            }
            SessionEncryptionKeySource::EncryptionKey(key) => {
                args.extend(strings(&["--key", &key]));
            }
        }

        Ok(self
            .runner()
            .run(&args, "9918-20782-3163")?
            .trim()
            .to_owned())
    }

    fn cas_attest(&self, request: &CasAttestRequest) -> Result<CasIdentityKeysHash> {
        self.run_gated(commands::attest_args(request), "7520-30768-31405")?;
        self.set_default_cas(&request.cas_address)?;
        self.cas_keys(&request.cas_address)
    }

    fn cas_provision(&self, request: &CasProvisionRequest) -> Result<CasIdentityKeysHash> {
        let owner_config = CliTempFile::create_with_suffix(
            request.owner_config_toml.as_deref().unwrap_or(""),
            ".toml",
            self.workdir.as_deref(),
        )?;
        let args = commands::provision_args(request, owner_config.path_str());
        self.run_gated(args, "30592-24188-14496")?;
        self.set_default_cas(&request.cas_address)?;
        self.cas_keys(&request.cas_address)
    }

    fn cas_keys(&self, cas_address: &str) -> Result<CasIdentityKeysHash> {
        let cas_key_hash: String = self.show_identification("--cas-key-hash", cas_address)?;
        let cas_software_key_hash =
            self.show_identification("--cas-software-key-hash", cas_address)?;

        Ok(CasIdentityKeysHash {
            cas_key_hash,
            cas_software_key_hash,
        })
    }

    fn cas_key_from_attestation_report(&self, report_json: &str) -> Result<String> {
        report::cas_key_from_report(report_json)
    }

    fn is_cas_entry_readable(&self, _entry: &serde_json::Value) -> bool {
        // The `scone` binary owns the config format; there is nothing to pre-validate here.
        true
    }

    fn read_session(
        &self,
        cas: &CasAddress,
        name: &str,
        session_hash: Option<&str>,
    ) -> Result<Option<String>> {
        let args = commands::session_read_args(cas, name, session_hash);
        let result = self.runner().raw(&args);
        match result.exit_code {
            0 => Ok(Some(result.stdout)),
            // The CLI reserves exit code 2 for "session not found".
            2 => Ok(None),
            code => bail!(
                "Scone CLI command failed with exit code {code} (ERROR 129012-1221-72811): {}",
                result.stderr
            ),
        }
    }

    fn list_sessions(&self, cas: &CasAddress, path: &str) -> Result<Vec<String>> {
        let args = commands::session_list_args(cas, path);
        let stdout = self.runner().run(&args, "50013-8801-3392")?;
        Ok(stdout
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_owned)
            .collect())
    }

    fn create_session(&self, cas: &CasAddress, yaml: &str, sign: bool) -> Result<String> {
        self.upload_session("create", cas, yaml, sign, "50014-1029-7745")
    }

    fn update_session(&self, cas: &CasAddress, yaml: &str, sign: bool) -> Result<String> {
        self.upload_session("update", cas, yaml, sign, "50015-6673-2201")
    }

    fn verify_audit_log(&self, request: &AuditLogRequest) -> Result<CommandOutput> {
        let args = version_gate::filter_for_installed_cli(
            &self.runner(),
            commands::audit_log_args(request),
        )?;
        let result = self.runner().raw(&args);
        Ok(CommandOutput {
            exit_code: result.exit_code,
            stdout: result.stdout,
            stderr: result.stderr,
        })
    }

    fn audit_log_checkpoints(&self, request: &CheckpointsRequest) -> Result<String> {
        let args = commands::checkpoints_args(request);
        Ok(self
            .runner()
            .run(&args, "50017-7204-1163")?
            .trim()
            .to_owned())
    }
}

impl SconeCli {
    fn set_default_cas(&self, cas_address: &str) -> Result<()> {
        let args = strings(&["cas", "set-default", cas_address]);
        self.runner().run(&args, "3674-20175-10692").map(|_| ())
    }

    fn show_identification(&self, flag: &str, cas_address: &str) -> Result<String> {
        let args = strings(&["cas", "show-identification", flag, cas_address]);
        Ok(self
            .runner()
            .run(&args, "6621-27685-4998")?
            .trim()
            .to_owned())
    }
}

fn strings(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_owned()).collect()
}
