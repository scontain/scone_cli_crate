//! Pure builders: typed request in, `scone` argument vector out. No process is started here.

use chrono::{DateTime, Utc};
use scone_cli_api::{
    AttestationSettings, AttestationSource, AuditLogRequest, CasAddress, CasAttestRequest,
    CasProvisionRequest, CheckpointsRequest, K_MRSIGNER_DB,
};

fn strings(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_owned()).collect()
}

fn date(time: &DateTime<Utc>) -> String {
    time.format("%Y-%m-%d").to_string()
}

/// Verifier flags shared by `cas attest`, `cas provision ... with-attestation` and audit logs.
pub(crate) fn attestation_flags(settings: &AttestationSettings) -> Vec<String> {
    let mut args = Vec::new();
    let mut flag = |enabled: bool, name: &str| {
        if enabled {
            args.push(name.to_owned());
        }
    };
    flag(
        settings.accept_group_out_of_date,
        "--accept-group-out-of-date",
    );
    flag(
        settings.accept_configuration_needed,
        "--accept-configuration-needed",
    );
    flag(
        settings.accept_sw_hardening_needed,
        "--accept-sw-hardening-needed",
    );
    flag(
        settings.accept_revoked_pck_certs,
        "--accept-revoked-pcs-certs",
    );
    flag(
        settings.accept_unverifiable_pcs_certs,
        "--accept-unverifiable-pcs-certs",
    );
    flag(settings.ignore_signer, "--only_for_testing-ignore-signer");
    flag(settings.accept_debug_enclave, "--only_for_testing-debug");
    flag(settings.trust_any, "--only_for_testing-trust-any");

    if settings.fail_on_any_advisory {
        args.push("--fail-on-any-advisory".to_owned());
    } else if let Some(advisories) = &settings.ignore_advisories {
        args.extend(["--ignore-advisories".to_owned(), advisories.join(",")]);
    }
    for mrenclave in &settings.mrenclave {
        args.extend(["--mrenclave".to_owned(), mrenclave.clone()]);
    }
    match (&settings.mrsigner, settings.ignore_signer) {
        (Some(mrsigner), _) => args.extend(["--mrsigner".to_owned(), mrsigner.clone()]),
        // Same rule as the in-process backend: no explicit signer means the production CAS signer.
        (None, false) => args.extend(["--mrsigner".to_owned(), K_MRSIGNER_DB.to_owned()]),
        (None, true) => {}
    }
    if let Some(isvprodid) = settings.isvprodid {
        args.extend(["--isvprodid".to_owned(), isvprodid.to_string()]);
    }
    if let Some(isvsvn) = settings.isvsvn {
        args.extend(["--isvsvn".to_owned(), isvsvn.to_string()]);
    }
    args
}

pub(crate) fn attest_args(request: &CasAttestRequest) -> Vec<String> {
    let mut args = strings(&["cas", "attest", &request.cas_address]);
    if let Some(cas_key_hash) = &request.cas_key_hash {
        args.extend(["-c".to_owned(), cas_key_hash.clone()]);
    }
    if request.allow_cas_owner_secret_access {
        args.push("--allow-cas-owner-secret-access".to_owned());
    }
    args.extend(["--retries".to_owned(), request.retries.to_string()]);
    if let Some(time) = &request.verification_time {
        args.extend(["--verification-time".to_owned(), date(time)]);
    }
    match &request.source {
        AttestationSource::Online {
            allow_unprovisioned,
        } => {
            if *allow_unprovisioned {
                args.push("--only_for_testing_allow-unprovisioned-cas".to_owned());
            }
        }
        AttestationSource::Offline { report_path, nonce } => {
            args.extend([
                "--nonce".to_owned(),
                nonce.clone(),
                "--offline-report".to_owned(),
                report_path.to_string_lossy().into_owned(),
            ]);
        }
    }
    args.extend(attestation_flags(&request.settings));
    args
}

pub(crate) fn provision_args(
    request: &CasProvisionRequest,
    owner_config_path: &str,
) -> Vec<String> {
    let mut args = strings(&[
        "cas",
        "provision",
        &request.cas_address,
        "-c",
        &request.cas_key_hash,
        "--token",
        &request.token,
        "--config-file",
        owner_config_path,
    ]);
    if let Some(database_key) = &request.database_key {
        args.extend(["--database-key".to_owned(), database_key.clone()]);
    }
    args.extend(["--retries".to_owned(), request.max_retries.to_string()]);
    if let Some(settings) = &request.attestation {
        args.push("with-attestation".to_owned());
        if let Some(time) = &request.verification_time {
            args.extend(["--verification-time".to_owned(), date(time)]);
        }
        args.extend(attestation_flags(settings));
    }
    args
}

pub(crate) fn session_read_args(
    cas: &CasAddress,
    name: &str,
    session_hash: Option<&str>,
) -> Vec<String> {
    let mut args = strings(&[
        "session",
        "read",
        "--cas",
        &cas.address,
        "--cas-key",
        &cas.cas_key,
    ]);
    if let Some(hash) = session_hash {
        args.extend(["--session-hash".to_owned(), hash.to_owned()]);
    }
    args.push(name.to_owned());
    args
}

pub(crate) fn session_list_args(cas: &CasAddress, path: &str) -> Vec<String> {
    strings(&[
        "session",
        "list",
        "--cas",
        &cas.address,
        "--cas-key",
        &cas.cas_key,
        path,
    ])
}

pub(crate) fn session_upload_args(verb: &str, cas: &CasAddress, file: &str) -> Vec<String> {
    strings(&[
        "session",
        verb,
        "--cas",
        &cas.address,
        "--cas-key",
        &cas.cas_key,
        file,
    ])
}

pub(crate) fn audit_log_args(request: &AuditLogRequest) -> Vec<String> {
    let verb = if request.attestation.is_some() {
        "attest-audit-log"
    } else {
        "verify-audit-log"
    };
    let mut args = strings(&["cas", verb]);
    let mut option = |name: &str, value: Option<String>| {
        if let Some(value) = value {
            args.extend([name.to_owned(), value]);
        }
    };
    option("--cas", request.cas.clone());
    option("--cas-key-hash", request.cas_key_hash.clone());
    option("--predecessor", request.predecessor.clone());
    option("--last", request.last.clone());
    option(
        "--checkpoints-json",
        request
            .checkpoints_json
            .as_ref()
            .map(|p| p.to_string_lossy().into_owned()),
    );
    if request.print_log {
        args.push("--print-log".to_owned());
    }
    if let Some(settings) = &request.attestation {
        args.extend(attestation_flags(settings));
    }
    args.push(request.log_file_path.to_string_lossy().into_owned());
    args
}

pub(crate) fn checkpoints_args(request: &CheckpointsRequest) -> Vec<String> {
    let mut args = strings(&["cas", "get-audit-log-checkpoints"]);
    if let Some(cas) = &request.cas {
        args.extend(["--cas".to_owned(), cas.clone()]);
    }
    if let Some(min) = request.min_sequence_number {
        args.extend(["--min-sequence-number".to_owned(), min.to_string()]);
    }
    if let Some(max) = request.max_sequence_number {
        args.extend(["--max-sequence-number".to_owned(), max.to_string()]);
    }
    args
}

#[cfg(test)]
mod tests;
