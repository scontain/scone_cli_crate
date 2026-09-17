//! This crate defines the traits and types for the SCONE CLI API, which is implemented by `scone_cli_public` (exec).
mod api;
mod types;

pub use api::SconeCliApi;
pub use types::{
    AttestationSettings, AttestationSource, AuditLogRequest, CasAddress, CasAttestRequest,
    CasIdentityKeysHash, CasProvisionRequest, CheckpointsRequest, CommandOutput,
    DEFAULT_NUM_OF_CAS_ATTEST_RETRIES, EnclaveSignerSource, ISV_PROD_ID_DB, ISV_SVN_DB,
    K_MRSIGNER_DB, SessionEncryptionKeySource,
};

#[cfg(test)]
mod tests;
