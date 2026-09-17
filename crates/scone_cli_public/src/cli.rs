use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use scone_cli_api::{
    AuditLogRequest, CasAddress, CasAttestRequest, CasIdentityKeys, CasProvisionRequest,
    CheckpointsRequest, CommandOutput, SconeCliApi,
};

use crate::{commands, report, runner::Runner, session_file::SessionFile, version_gate};

/// Runs SCONE CLI operations against one config file by executing the `scone` binary.
///
/// `SconeCli::new()` has no config and only supports the operations that do not need one.
#[derive(Clone, Debug, Default)]
pub struct SconeCli {
    config: Option<PathBuf>,
}

impl SconeCli {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_config(config_path: impl Into<PathBuf>) -> Self {
        Self {
            config: Some(config_path.into()),
        }
    }

    fn runner(&self) -> Runner<'_> {
        Runner::new(self.config.as_deref())
    }

    fn require_config(&self, operation: &str) -> Result<()> {
        if self.config.is_none() {
            bail!(
                "`{operation}` needs a SCONE CLI config; create the client with SconeCli::with_config(<path>)."
            );
        }
        Ok(())
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
        self.require_config(verb)?;
        let body = if sign {
            self.sign_session(yaml)?
        } else {
            yaml.to_owned()
        };
        let file = SessionFile::create(&body)?;
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
        self.require_config("key_hash")?;
        let args = strings(&["self", "show-key-hash"]);
        Ok(self
            .runner()
            .run(&args, "50011-2231-9081")?
            .trim()
            .to_owned())
    }

    fn session_signing_public_key(&self) -> Result<String> {
        self.require_config("session_signing_public_key")?;
        let args = strings(&["self", "show-session-signing-key"]);
        Ok(self.runner().run(&args, "9808-322-4776")?.trim().to_owned())
    }

    fn validate_session(&self, yaml: &str) -> Result<()> {
        let file = SessionFile::create(yaml)?;
        let args = strings(&["session", "check", file.path_str()]);
        self.runner().run(&args, "50012-4417-1290").map(|_| ())
    }

    fn session_hash(&self, yaml: &str) -> Result<String> {
        let file = SessionFile::create(yaml)?;
        let args = strings(&["session", "calculate-hash", file.path_str()]);
        Ok(self
            .runner()
            .run(&args, "19175-9146-3013")?
            .trim()
            .to_owned())
    }

    fn sign_session(&self, yaml: &str) -> Result<String> {
        self.require_config("sign_session")?;
        let file = SessionFile::create(yaml)?;
        let args = strings(&["session", "sign", file.path_str()]);
        Ok(self
            .runner()
            .run(&args, "28666-19528-6399")?
            .trim()
            .to_owned())
    }

    fn encrypt_session(&self, yaml: &str, cas: Option<&str>) -> Result<String> {
        self.require_config("encrypt_session")?;
        let file = SessionFile::create(yaml)?;
        let mut args = strings(&["session", "encrypt", file.path_str()]);
        if let Some(cas) = cas {
            args.extend(strings(&["--cas", cas]));
        }
        Ok(self
            .runner()
            .run(&args, "9918-20782-3163")?
            .trim()
            .to_owned())
    }

    fn cas_attest(&self, request: &CasAttestRequest) -> Result<CasIdentityKeys> {
        self.require_config("cas_attest")?;
        self.run_gated(commands::attest_args(request), "7520-30768-31405")?;
        self.set_default_cas(&request.cas_address)?;
        self.cas_keys(&request.cas_address)
    }

    fn cas_provision(&self, request: &CasProvisionRequest) -> Result<CasIdentityKeys> {
        self.require_config("cas_provision")?;
        let owner_config = SessionFile::create_with_suffix(
            request.owner_config_toml.as_deref().unwrap_or(""),
            ".toml",
        )?;
        let args = commands::provision_args(request, owner_config.path_str());
        self.run_gated(args, "40001-1000-0001")?;
        self.set_default_cas(&request.cas_address)?;
        self.cas_keys(&request.cas_address)
    }

    fn cas_keys(&self, cas_address: &str) -> Result<CasIdentityKeys> {
        self.require_config("cas_keys")?;
        let cas_key = self.show_identification("--cas-key", cas_address)?;
        // Older CAS versions have no software key; that is "absent", not an error.
        let cas_software_key = self
            .show_identification("--cas-software-key", cas_address)
            .ok();
        Ok(CasIdentityKeys {
            cas_key: Some(cas_key),
            cas_software_key,
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
        self.require_config("read_session")?;
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
        self.require_config("list_sessions")?;
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
        self.require_config("verify_audit_log")?;
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
        self.require_config("audit_log_checkpoints")?;
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
        self.runner().run(&args, "40002-1000-0002").map(|_| ())
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
