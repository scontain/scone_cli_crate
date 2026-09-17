use super::*;

#[test]
fn prod_defaults_pin_the_production_signer() {
    let settings = AttestationSettings::prod_defaults();
    assert_eq!(settings.mrsigner.as_deref(), Some(K_MRSIGNER_DB));
    assert_eq!(
        (settings.isvprodid, settings.isvsvn),
        (Some(41316), Some(5))
    );
    assert!(settings.accept_group_out_of_date && !settings.accept_revoked_pck_certs);
}

#[test]
fn online_request_is_strict_and_offline_request_is_td_build() {
    let online = CasAttestRequest::online("https://cas:8081");
    assert_eq!(online.settings, AttestationSettings::default());
    assert_eq!(online.retries, Some(3));

    let offline = CasAttestRequest::offline("https://cas:8081", "/tmp/report.json", "n");
    assert_eq!(offline.settings, AttestationSettings::prod_defaults());
    assert!(offline.settings.allow_cas_owner_secret_access);
}

#[test]
fn command_output_from_tuple() {
    let output = CommandOutput::from((2, "out".into(), "err".into()));
    assert!(!output.success());
    assert_eq!(output.stderr, "err");
}
