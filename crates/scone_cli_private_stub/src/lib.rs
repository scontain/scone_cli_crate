//! This crate provides a stub implementation of the "in-process" backend.
//!
//! It only stands in for the private backend when the dependency graph is resolved, so that
//! builds without access to it still resolve. Compiling it is an error: a build that selects the
//! private backend has to patch in the real crate.

#[cfg(not(feature = "allow-stub"))]
compile_error!(
    "scone_cli_private is the stub: patch in the private backend (e.g. \
     `cargo --config .cargo/scone-private.toml ...`) or build with the public backend"
);

use anyhow::{Result, bail};
pub use scone_cli_api::*;

pub struct SconeCli {
    _private: (),
}

impl SconeCli {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for SconeCli {
    fn default() -> Self {
        Self::new()
    }
}

const STUB_MSG: &str = "scone_cli_private stub was called: this build does not include the private scone-policy-sdk implementation (patch `scone_cli_private` in internal builds)";

impl SconeCliApi for SconeCli {
    fn key_hash(&self) -> Result<String> {
        bail!(STUB_MSG)
    }

    fn session_signing_public_key(&self) -> Result<String> {
        bail!(STUB_MSG)
    }

    fn validate_session(&self, _yaml: &str) -> Result<()> {
        bail!(STUB_MSG)
    }

    fn session_hash(&self, _yaml: &str) -> Result<String> {
        bail!(STUB_MSG)
    }

    fn sign_session(&self, _yaml: &str) -> Result<String> {
        bail!(STUB_MSG)
    }

    fn encrypt_session(
        &self,
        _yaml: &str,
        _key_source: SessionEncryptionKeySource,
    ) -> Result<String> {
        bail!(STUB_MSG)
    }

    fn cas_attest(&self, _request: &CasAttestRequest) -> Result<CasIdentityKeysHash> {
        bail!(STUB_MSG)
    }

    fn cas_provision(&self, _request: &CasProvisionRequest) -> Result<CasIdentityKeysHash> {
        bail!(STUB_MSG)
    }

    fn cas_keys(&self, _cas_address: &str) -> Result<CasIdentityKeysHash> {
        bail!(STUB_MSG)
    }

    fn cas_key_from_attestation_report(&self, _report_json: &str) -> Result<String> {
        bail!(STUB_MSG)
    }

    fn is_cas_entry_readable(&self, _entry: &serde_json::Value) -> bool {
        // The `scone` binary owns the config format; there is nothing to pre-validate here.
        true
    }

    fn read_session(
        &self,
        _cas: &CasAddress,
        _name: &str,
        _session_hash: Option<&str>,
    ) -> Result<Option<String>> {
        bail!(STUB_MSG)
    }

    fn list_sessions(&self, _cas: &CasAddress, _path: &str) -> Result<Vec<String>> {
        bail!(STUB_MSG)
    }

    fn create_session(&self, _cas: &CasAddress, _yaml: &str, _sign: bool) -> Result<String> {
        bail!(STUB_MSG)
    }

    fn update_session(&self, _cas: &CasAddress, _yaml: &str, _sign: bool) -> Result<String> {
        bail!(STUB_MSG)
    }

    fn verify_audit_log(&self, _request: &AuditLogRequest) -> Result<CommandOutput> {
        bail!(STUB_MSG)
    }

    fn audit_log_checkpoints(&self, _request: &CheckpointsRequest) -> Result<String> {
        bail!(STUB_MSG)
    }

    fn config_path(&self) -> Option<&std::path::Path> {
        None
    }
}
