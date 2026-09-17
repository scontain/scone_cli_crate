//! Drops attestation flags that the installed `scone` is too old to understand.

use anyhow::Result;
use log::warn;
use semver::{Version, VersionReq};

use crate::runner::Runner;

struct VersionedArg {
    flag: &'static str,
    supported: VersionReq,
}

fn registry() -> Vec<VersionedArg> {
    vec![
        VersionedArg {
            flag: "--accept-unverifiable-pcs-certs",
            supported: ">=7.0.0".parse().unwrap(),
        },
        VersionedArg {
            flag: "--accept-revoked-pcs-certs",
            supported: ">=7.0.0".parse().unwrap(),
        },
    ]
}

pub(crate) fn filter_args_for_scone_cli(
    args: Vec<String>,
    scone_cli_version: &Version,
) -> Vec<String> {
    let registry = registry();
    // Pre-release builds (7.0.0-alpha.4) count as their release for gating purposes.
    let base_version = Version::new(
        scone_cli_version.major,
        scone_cli_version.minor,
        scone_cli_version.patch,
    );
    let mut out = Vec::with_capacity(args.len());
    for arg in args {
        match registry.iter().find(|entry| entry.flag == arg.as_str()) {
            Some(entry) if !entry.supported.matches(&base_version) => {
                warn!(
                    "Dropping attest arg '{arg}' — not supported by Scone CLI {scone_cli_version}"
                );
            }
            _ => out.push(arg),
        }
    }
    out
}

fn contains_version_gated_arg(args: &[String]) -> bool {
    let registry = registry();
    args.iter()
        .any(|arg| registry.iter().any(|entry| entry.flag == arg.as_str()))
}

/// Asks the installed CLI for its version only when a gated flag is present.
pub(crate) fn filter_for_installed_cli(
    runner: &Runner<'_>,
    args: Vec<String>,
) -> Result<Vec<String>> {
    if !contains_version_gated_arg(&args) {
        return Ok(args);
    }
    let version = installed_version(runner)?;
    Ok(filter_args_for_scone_cli(args, &version))
}

fn installed_version(runner: &Runner<'_>) -> Result<Version> {
    use anyhow::Context;
    let output = runner.run(&["--version".to_owned()], "31045-9872-4516")?;
    let word = output
        .split_whitespace()
        .last()
        .with_context(|| format!("Unexpected empty output from scone --version: '{output}'"))?;
    Version::parse(word).with_context(|| {
        format!("Could not parse Scone CLI version: '{word}' is not a valid semver")
    })
}

#[cfg(test)]
mod tests;
