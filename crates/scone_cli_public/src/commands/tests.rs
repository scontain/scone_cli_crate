use super::*;
use chrono::TimeZone;

fn has_pair(args: &[String], flag: &str, value: &str) -> bool {
    args.windows(2).any(|w| w[0] == flag && w[1] == value)
}

#[test]
fn default_settings_pin_the_production_signer() {
    let args = attestation_flags(&AttestationSettings::default());
    assert_eq!(args, ["--mrsigner", K_MRSIGNER_DB]);
}

#[test]
fn ignore_signer_drops_the_default_signer() {
    let settings = AttestationSettings {
        ignore_signer: true,
        ..Default::default()
    };
    assert_eq!(
        attestation_flags(&settings),
        ["--only_for_testing-ignore-signer"]
    );
}

#[test]
fn fail_on_any_advisory_wins_over_an_ignore_list() {
    let settings = AttestationSettings {
        fail_on_any_advisory: true,
        ignore_advisories: Some(vec!["INTEL-SA-1".into()]),
        ..Default::default()
    };
    let args = attestation_flags(&settings);
    assert!(args.contains(&"--fail-on-any-advisory".to_owned()));
    assert!(!args.contains(&"--ignore-advisories".to_owned()));
}

#[test]
fn ignore_list_is_comma_joined() {
    let settings = AttestationSettings {
        ignore_advisories: Some(vec!["INTEL-SA-1".into(), "INTEL-SA-2".into()]),
        ..Default::default()
    };
    assert!(has_pair(
        &attestation_flags(&settings),
        "--ignore-advisories",
        "INTEL-SA-1,INTEL-SA-2"
    ));
}

#[test]
fn online_attest_is_a_plain_command_line() {
    let mut request = CasAttestRequest::online("https://cas:8081");
    request.cas_key_hash = Some("KEY".into());
    request.verification_time = Some(Utc.with_ymd_and_hms(2026, 5, 10, 12, 0, 0).unwrap());
    let args = attest_args(&request);
    assert_eq!(&args[..3], ["cas", "attest", "https://cas:8081"]);
    assert!(has_pair(&args, "-c", "KEY"));
    assert!(has_pair(&args, "--retries", "3"));
    assert!(has_pair(&args, "--verification-time", "2026-05-10"));
    assert!(!args.contains(&"--offline-report".to_owned()));
}

#[test]
fn offline_attest_passes_report_and_nonce() {
    let args = attest_args(&CasAttestRequest::offline(
        "https://cas:8081",
        "/tmp/r.json",
        "N",
    ));
    assert!(has_pair(&args, "--nonce", "N"));
    assert!(has_pair(&args, "--offline-report", "/tmp/r.json"));
    assert!(args.contains(&"--allow-cas-owner-secret-access".to_owned()));
    assert!(has_pair(&args, "--isvprodid", "41316"));
}

#[test]
fn provision_puts_attestation_flags_after_with_attestation() {
    let mut request = CasProvisionRequest::new("https://cas:8081", "KEY", "TOKEN");
    request.database_key = Some("DB".into());
    request.attestation = Some(AttestationSettings {
        accept_group_out_of_date: true,
        ..Default::default()
    });
    let args = provision_args(&request, "/tmp/owner.toml");
    let marker = args
        .iter()
        .position(|a| a == "with-attestation")
        .expect("with-attestation");
    assert!(args[marker..].contains(&"--accept-group-out-of-date".to_owned()));
    assert!(has_pair(&args, "--config-file", "/tmp/owner.toml"));
    assert!(has_pair(&args, "--database-key", "DB"));

    request.attestation = None;
    assert!(!provision_args(&request, "/tmp/owner.toml").contains(&"with-attestation".to_owned()));
}

#[test]
fn read_and_list_use_the_documented_option_order() {
    let cas = CasAddress::new("https://cas:8081", "KEY");
    assert_eq!(
        session_read_args(&cas, "/a/b", Some("H")),
        [
            "session",
            "read",
            "--cas",
            "https://cas:8081",
            "--cas-key",
            "KEY",
            "--session-hash",
            "H",
            "/a/b"
        ]
    );
    assert_eq!(
        session_list_args(&cas, "/a"),
        [
            "session",
            "list",
            "--cas",
            "https://cas:8081",
            "--cas-key",
            "KEY",
            "/a"
        ]
    );
}

#[test]
fn audit_log_verb_follows_attestation() {
    let mut request = AuditLogRequest {
        log_file_path: "/tmp/log".into(),
        print_log: true,
        ..Default::default()
    };
    let args = audit_log_args(&request);
    assert_eq!(&args[..2], ["cas", "verify-audit-log"]);
    assert_eq!(args.last().map(String::as_str), Some("/tmp/log"));
    assert!(args.contains(&"--print-log".to_owned()));

    request.attestation = Some(AttestationSettings::default());
    assert_eq!(&audit_log_args(&request)[..2], ["cas", "attest-audit-log"]);
}

#[test]
fn checkpoint_bounds_are_optional() {
    assert_eq!(
        checkpoints_args(&CheckpointsRequest::default()),
        ["cas", "get-audit-log-checkpoints"]
    );
    let args = checkpoints_args(&CheckpointsRequest {
        min_sequence_number: Some(4),
        ..Default::default()
    });
    assert!(has_pair(&args, "--min-sequence-number", "4"));
}
