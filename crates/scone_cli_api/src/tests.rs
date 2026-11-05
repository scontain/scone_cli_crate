use super::*;

#[test]
fn prod_defaults_pin_the_production_signer() {
    let settings = AttestationSettings::prod_defaults();
    assert_eq!(settings.signer_info, EnclaveSignerSource::Production);
    assert!(settings.accept_group_out_of_date && !settings.accept_revoked_pck_certs);
}

#[test]
fn command_output_from_tuple() {
    let output = CommandOutput::from((2, "out".into(), "err".into()));
    assert!(!output.success());
    assert_eq!(output.stderr, "err");
}
