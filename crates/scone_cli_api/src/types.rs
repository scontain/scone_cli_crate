use std::path::PathBuf;

use chrono::{DateTime, Utc};

/// MRSIGNER of the production SCONE CAS enclave.
pub const K_MRSIGNER_DB: &str = "195e5a6df987d6a515dd083750c1ea352283f8364d3ec9142b0d593988c6ed2d";

/// Outcome of an operation whose exit status is part of its meaning (audit-log verification).
///
/// Operational failures (bad input, unreachable CAS, ...) are `Err`; a verification that ran but
/// did not pass is `Ok` with a non-zero `exit_code`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CommandOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl CommandOutput {
    #[must_use]
    pub fn success(&self) -> bool {
        self.exit_code == 0
    }
}

impl From<(i32, String, String)> for CommandOutput {
    fn from((exit_code, stdout, stderr): (i32, String, String)) -> Self {
        Self {
            exit_code,
            stdout,
            stderr,
        }
    }
}

/// A CAS to talk to: where it is and which `CAS_KEY` it must present.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CasAddress {
    pub address: String,
    pub cas_key: String,
}

impl CasAddress {
    pub fn new(address: impl Into<String>, cas_key: impl Into<String>) -> Self {
        Self {
            address: address.into(),
            cas_key: cas_key.into(),
        }
    }
}

/// Identity keys of an attested CAS.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CasIdentityKeys {
    pub cas_key: Option<String>,
    pub cas_software_key: Option<String>,
}

impl CasIdentityKeys {
    /// Returns `(cas_key, cas_software_key)`, failing if either is missing.
    pub fn into_required(self) -> anyhow::Result<(String, String)> {
        let cas_key = self
            .cas_key
            .ok_or_else(|| anyhow::anyhow!("The CAS did not expose a CAS key."))?;
        let cas_software_key = self
            .cas_software_key
            .ok_or_else(|| anyhow::anyhow!("The CAS did not expose a CAS software key."))?;
        Ok((cas_key, cas_software_key))
    }
}

/// What a verifier accepts when attesting a CAS (or checking an audit log).
///
/// With everything left at its default the CAS must be the production SCONE CAS enclave
/// (`K_MRSIGNER_DB`) with no tolerated TCB problems.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AttestationSettings {
    pub accept_group_out_of_date: bool,
    pub accept_configuration_needed: bool,
    pub accept_sw_hardening_needed: bool,
    pub accept_revoked_pck_certs: bool,
    pub accept_unverifiable_pcs_certs: bool,
    /// `Some(list)` tolerates exactly these advisories; `None` tolerates all unless
    /// `fail_on_any_advisory` is set.
    pub ignore_advisories: Option<Vec<String>>,
    pub fail_on_any_advisory: bool,
    pub mrenclave: Vec<String>,
    pub mrsigner: Option<String>,
    pub isvprodid: Option<u16>,
    pub isvsvn: Option<u16>,
    pub ignore_signer: bool,
    pub accept_debug_enclave: bool,
    pub trust_any: bool,
}

impl AttestationSettings {
    /// The tolerant settings `scone-td-build` uses when attesting a CAS.
    #[must_use]
    pub fn td_build_defaults() -> Self {
        Self {
            accept_group_out_of_date: true,
            accept_configuration_needed: true,
            accept_sw_hardening_needed: true,
            mrsigner: Some(K_MRSIGNER_DB.to_owned()),
            isvprodid: Some(41316),
            isvsvn: Some(5),
            ..Self::default()
        }
    }
}

/// Where the attestation evidence comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttestationSource {
    /// Ask the running CAS. `allow_unprovisioned` accepts a CAS that was never provisioned
    /// (testing only).
    Online { allow_unprovisioned: bool },
    /// Use a DCAP report saved earlier; `nonce` is the report nonce that was requested.
    Offline { report_path: PathBuf, nonce: String },
}

/// Attest a CAS. On success the CAS is remembered in the CLI config and becomes its default CAS.
#[derive(Clone, Debug)]
pub struct CasAttestRequest {
    pub cas_address: String,
    pub source: AttestationSource,
    /// Expected `CAS_KEY`, if already known.
    pub cas_key_hash: Option<String>,
    /// Whether the attested CAS may inject the owner-secret database key.
    pub allow_cas_owner_secret_access: bool,
    pub retries: u32,
    /// Evaluate the TCB as of this time instead of now.
    pub verification_time: Option<DateTime<Utc>>,
    pub settings: AttestationSettings,
}

impl CasAttestRequest {
    /// Attest a running CAS with production defaults and 3 retries.
    pub fn online(cas_address: impl Into<String>) -> Self {
        Self {
            cas_address: cas_address.into(),
            source: AttestationSource::Online {
                allow_unprovisioned: false,
            },
            cas_key_hash: None,
            allow_cas_owner_secret_access: false,
            retries: 3,
            verification_time: None,
            settings: AttestationSettings::default(),
        }
    }

    /// Attest from an offline report using the `scone-td-build` settings.
    pub fn offline(
        cas_address: impl Into<String>,
        report_path: impl Into<PathBuf>,
        nonce: impl Into<String>,
    ) -> Self {
        Self {
            source: AttestationSource::Offline {
                report_path: report_path.into(),
                nonce: nonce.into(),
            },
            allow_cas_owner_secret_access: true,
            settings: AttestationSettings::td_build_defaults(),
            ..Self::online(cas_address)
        }
    }
}

/// Provision a freshly started CAS. On success the CAS is remembered in the CLI config, becomes
/// its default CAS, and its new identity keys are returned.
#[derive(Clone, Debug)]
pub struct CasProvisionRequest {
    pub cas_address: String,
    /// `CAS_KEY` printed by the CAS while waiting to be provisioned.
    pub cas_key_hash: String,
    /// 16-byte provisioning token, hex encoded.
    pub token: String,
    /// Optional 32-byte database key, hex encoded.
    pub database_key: Option<String>,
    /// Owner configuration as TOML; `None` means the default configuration.
    pub owner_config_toml: Option<String>,
    /// `Some` attests the CAS while provisioning; `None` skips attestation.
    pub attestation: Option<AttestationSettings>,
    pub verification_time: Option<DateTime<Utc>>,
    pub max_retries: u32,
}

impl CasProvisionRequest {
    pub fn new(
        cas_address: impl Into<String>,
        cas_key_hash: impl Into<String>,
        token: impl Into<String>,
    ) -> Self {
        Self {
            cas_address: cas_address.into(),
            cas_key_hash: cas_key_hash.into(),
            token: token.into(),
            database_key: None,
            owner_config_toml: None,
            attestation: None,
            verification_time: None,
            max_retries: 3,
        }
    }
}

/// Verify a CAS audit log; give `attestation` to also attest the CAS that signed it.
#[derive(Clone, Debug, Default)]
pub struct AuditLogRequest {
    pub log_file_path: PathBuf,
    /// CAS to fetch online checkpoints from (defaults to the config's default CAS).
    pub cas: Option<String>,
    pub cas_key_hash: Option<String>,
    pub print_log: bool,
    pub predecessor: Option<String>,
    pub last: Option<String>,
    /// Checkpoint file for air-gapped verification; replaces the online lookup.
    pub checkpoints_json: Option<PathBuf>,
    pub attestation: Option<AttestationSettings>,
}

/// Fetch audit-log checkpoints from a CAS.
#[derive(Clone, Debug, Default)]
pub struct CheckpointsRequest {
    pub cas: Option<String>,
    pub min_sequence_number: Option<u64>,
    pub max_sequence_number: Option<u64>,
}
