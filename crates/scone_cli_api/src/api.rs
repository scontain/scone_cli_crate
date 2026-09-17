use std::path::Path;

use anyhow::Result;

use crate::types::{
    AuditLogRequest, CasAddress, CasAttestRequest, CasIdentityKeys, CasProvisionRequest,
    CheckpointsRequest, CommandOutput,
};

/// Everything an application can ask of the SCONE CLI.
///
/// Sessions travel as YAML/JSON `&str`, hashes and keys as `String`; no backend types leak out.
/// Methods marked *needs config* fail unless the `SconeCli` was built with `with_config`; the
/// others work on any instance.
///
/// The trait is object safe, so `&dyn SconeCliApi` works for injection and mocking.
pub trait SconeCliApi {
    /// The config file this instance operates on, if any.
    fn config_path(&self) -> Option<&Path>;

    /// Key hash of the identity in the config. *Needs config.*
    fn key_hash(&self) -> Result<String>;

    /// Public key that session signatures made with this config verify against. *Needs config.*
    fn session_signing_public_key(&self) -> Result<String>;

    /// Parses a session and reports problems, like `scone session check`.
    fn validate_session(&self, yaml: &str) -> Result<()>;

    /// Hash of an unsigned or signed session.
    fn session_hash(&self, yaml: &str) -> Result<String>;

    /// Signs a session with the config identity (adds a signature if already signed) and returns
    /// the signed-session JSON. *Needs config.*
    fn sign_session(&self, yaml: &str) -> Result<String>;

    /// Signs (if needed) and encrypts a session for `cas`, or for the default CAS when `None`,
    /// returning the encrypted-session JSON. *Needs config.*
    fn encrypt_session(&self, yaml: &str, cas: Option<&str>) -> Result<String>;

    /// Attests a CAS and stores it as the default CAS. *Needs config.*
    fn cas_attest(&self, request: &CasAttestRequest) -> Result<CasIdentityKeys>;

    /// Provisions a CAS and stores it as the default CAS. *Needs config.*
    fn cas_provision(&self, request: &CasProvisionRequest) -> Result<CasIdentityKeys>;

    /// Identity keys of a CAS already stored in the config. *Needs config.*
    fn cas_keys(&self, cas_address: &str) -> Result<CasIdentityKeys>;

    /// Extracts the `CAS_KEY` from a CAS attestation report (JSON).
    ///
    /// The in-process backend also decodes certificate-chain reports; the exec backend only
    /// understands reports that carry the key as a plain field and errors on the others.
    fn cas_key_from_attestation_report(&self, report_json: &str) -> Result<String>;

    /// Whether one `cas_db` entry of a config file can be read by this backend.
    fn is_cas_entry_readable(&self, entry: &serde_json::Value) -> bool;

    /// Session as YAML, or `None` if the CAS does not have it. *Needs config.*
    fn read_session(
        &self,
        cas: &CasAddress,
        name: &str,
        session_hash: Option<&str>,
    ) -> Result<Option<String>>;

    /// Names of the sessions below `path`. *Needs config.*
    fn list_sessions(&self, cas: &CasAddress, path: &str) -> Result<Vec<String>>;

    /// Creates a session and returns its hash. With `sign`, the config identity signs it first.
    /// *Needs config.*
    fn create_session(&self, cas: &CasAddress, yaml: &str, sign: bool) -> Result<String>;

    /// Updates a session and returns its new hash. With `sign`, the config identity signs it
    /// first. *Needs config.*
    fn update_session(&self, cas: &CasAddress, yaml: &str, sign: bool) -> Result<String>;

    /// Verifies an audit log. *Needs config.*
    fn verify_audit_log(&self, request: &AuditLogRequest) -> Result<CommandOutput>;

    /// Checkpoints as pretty-printed JSON. *Needs config.*
    fn audit_log_checkpoints(&self, request: &CheckpointsRequest) -> Result<String>;
}

/// Compile-time guard: the trait must stay object safe.
#[allow(dead_code)]
fn assert_object_safe(_: &dyn SconeCliApi) {}
