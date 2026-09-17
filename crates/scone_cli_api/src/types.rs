use std::path::PathBuf;

use chrono::{DateTime, Utc};

/// MRSIGNER of the production SCONE CAS enclave.
pub const K_MRSIGNER_DB: &str = "195e5a6df987d6a515dd083750c1ea352283f8364d3ec9142b0d593988c6ed2d";

/// ISVPRODID of the production SCONE CAS enclave.
pub const ISV_PROD_ID_DB: u16 = 41316;

/// ISVSVN of the production SCONE CAS enclave.
pub const ISV_SVN_DB: u16 = 5;

/// The default number of retries when attesting a CAS.
pub const DEFAULT_NUM_OF_CAS_ATTEST_RETRIES: u32 = 3;
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
    pub cas_key_hash: String,
}

impl CasAddress {
    pub fn new(address: impl Into<String>, cas_key_hash: impl Into<String>) -> Self {
        Self {
            address: address.into(),
            cas_key_hash: cas_key_hash.into(),
        }
    }

    pub fn get_address(&self) -> &str {
        &self.address
    }
}

/// Identity keys of an attested CAS.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CasIdentityKeysHash {
    pub cas_key_hash: String,
    pub cas_software_key_hash: String,
}

/// What a verifier accepts when attesting a CAS (or checking an audit log).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestationSettings {
    pub accept_group_out_of_date: bool,
    pub accept_configuration_needed: bool,
    pub accept_sw_hardening_needed: bool,
    /// Whether the attested CAS may inject the owner-secret database key.
    pub allow_cas_owner_secret_access: bool,
    pub accept_revoked_pck_certs: bool,
    pub accept_unverifiable_pcs_certs: bool,
    /// `Some(list)` tolerates exactly these advisories; `None` tolerates all unless
    /// `fail_on_any_advisory` is set.
    pub ignore_advisories: Option<Vec<String>>,
    pub fail_on_any_advisory: bool,
    pub mrenclave: Vec<String>,
    pub signer_info: EnclaveSignerSource,
    pub accept_debug_enclave: bool,
    pub trust_any: bool,
    pub allow_unprovisioned_cas: bool,
}

/// Specify the signer info of the CAS enclave to attest.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum EnclaveSignerSource {
    /// The production SCONE CAS enclave uses the well-known [`K_MRSIGNER_DB`], [`ISV_PROD_ID_DB`] and [`ISV_SVN_DB`].
    #[default]
    Production,
    /// Specify the signer info of the CAS enclave to attest.
    Custom {
        /// MRSIGNER of the CAS enclave.
        mrsigner: String,
        /// ISVPRODID of the CAS enclave.
        isvprodid: u16,
        /// ISVSVN of the CAS enclave.
        isvsvn: u16,
    },
    /// Ignore the signer info of the CAS enclave. This is only for testing and should never be used in production.
    IgnoreForTesting,
}

impl AttestationSettings {
    /// The tolerant settings uses when attesting a production CAS.
    #[must_use]
    pub fn prod_defaults() -> Self {
        Self {
            accept_group_out_of_date: true,
            accept_configuration_needed: true,
            accept_sw_hardening_needed: true,
            allow_cas_owner_secret_access: false,
            accept_revoked_pck_certs: false,
            accept_unverifiable_pcs_certs: false,
            ignore_advisories: None,
            fail_on_any_advisory: false,
            mrenclave: Vec::new(),
            signer_info: EnclaveSignerSource::Production,
            accept_debug_enclave: false,
            trust_any: false,
            allow_unprovisioned_cas: false,
        }
    }

    pub fn sgx_defaults(&mut self) -> &mut Self {
        self.accept_group_out_of_date = true;
        self.accept_configuration_needed = true;
        self.accept_sw_hardening_needed = true;

        self
    }

    pub fn isv_defaults(&mut self) -> &mut Self {
        self.signer_info = EnclaveSignerSource::Production;
        self
    }
}
#[derive(Clone, Debug)]
pub enum SessionEncryptionKeySource {
    /// Use a specified CAS address;
    CasAddress(String),
    /// Use a specified encryption key. Use `scone cas show-identification --session-encryption-key`
    EncryptionKey(String),
}

/// Where the attestation evidence comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttestationSource {
    Online,
    /// Use a DCAP report saved earlier; `nonce` is the report nonce that was requested.
    Offline {
        report_path: PathBuf,
        nonce: String,
    },
}

/// Attest a CAS. On success the CAS is remembered in the CLI config and becomes its default CAS.
#[derive(Clone, Debug)]
pub struct CasAttestRequest {
    pub cas_address: String,
    pub source: AttestationSource,

    /// Expected `CAS_KEY`, if already known.
    pub cas_key_hash: Option<String>,
    pub cas_software_key_hash: Option<String>,

    pub retries: Option<u32>,
    /// The date, in UTC, as of which the attestation collaterals are verified.
    /// Only the date is passed to the `scone` CLI (`--verification-time yyyy-mm-dd`);
    /// the time of day is ignored. `None` means now.
    pub verification_time: Option<DateTime<Utc>>,
    pub settings: AttestationSettings,
}

impl CasAttestRequest {
    /// Attest a running CAS with production defaults and 3 retries.
    pub fn online(cas_address: impl Into<String>) -> Self {
        Self {
            cas_address: cas_address.into(),
            source: AttestationSource::Online,
            cas_key_hash: None,
            cas_software_key_hash: None,
            retries: Some(DEFAULT_NUM_OF_CAS_ATTEST_RETRIES),
            verification_time: None,
            settings: AttestationSettings::prod_defaults(),
        }
    }

    /// Attest from an offline report
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
            settings: AttestationSettings::prod_defaults(),
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
    /// The date, in UTC, as of which the attestation collaterals are verified.
    /// Only the date is passed to the `scone` CLI (`--verification-time yyyy-mm-dd`);
    /// the time of day is ignored. `None` means now.
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
