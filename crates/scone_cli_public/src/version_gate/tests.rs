use super::*;

#[test]
fn drops_unsupported_registry_flags() {
    let v = Version::parse("6.0.6").unwrap();
    let out = filter_args_for_scone_cli(
        vec!["--accept-revoked-pcs-certs".into(), "--verbose".into()],
        &v,
    );
    assert_eq!(out, vec!["--verbose".to_string()]);
}

#[test]
fn keeps_supported_flags_on_prerelease() {
    let v = Version::parse("7.0.0-alpha.4").unwrap();
    let out = filter_args_for_scone_cli(vec!["--accept-revoked-pcs-certs".into()], &v);
    assert_eq!(out, vec!["--accept-revoked-pcs-certs".to_string()]);
}

#[test]
fn passes_through_non_registry_args() {
    let v = Version::parse("6.0.6").unwrap();
    let out = filter_args_for_scone_cli(vec!["--isvsvn".into(), "5".into()], &v);
    assert_eq!(out, vec!["--isvsvn".to_string(), "5".to_string()]);
}
