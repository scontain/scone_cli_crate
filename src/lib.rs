mod engine;

use anyhow::{Context, bail};
use log::{debug, info, warn};
use semver::{Version, VersionReq};
use std::{
    io::Write,
    path::{Path, PathBuf},
};
use tempfile::NamedTempFile;

pub use engine::*;

pub(crate) const K_MRSIGNER_DB: &str =
    "195e5a6df987d6a515dd083750c1ea352283f8364d3ec9142b0d593988c6ed2d";

pub enum OutputDest {
    Temp,
    Fixed(PathBuf),
}

fn write_to_dest(dest: &OutputDest, data: &[u8]) -> anyhow::Result<PersistedFile> {
    match dest {
        OutputDest::Temp => {
            let tmp = NamedTempFile::new()?;
            std::fs::write(tmp.path(), data)?;
            Ok(PersistedFile::Temp(tmp))
        }
        OutputDest::Fixed(path) => {
            std::fs::write(path, data)?;
            Ok(PersistedFile::Fixed(path.clone()))
        }
    }
}

pub enum PersistedFile {
    Temp(NamedTempFile),
    Fixed(PathBuf),
}

impl PersistedFile {
    pub fn path(&self) -> &Path {
        match self {
            PersistedFile::Temp(t) => t.path(),
            PersistedFile::Fixed(p) => p.as_path(),
        }
    }
}

struct VersionedArg {
    flag: &'static str,
    supported: VersionReq,
}

fn get_attest_arg_registry() -> Vec<VersionedArg> {
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

fn filter_args_for_scone_cli(args: Vec<String>, scone_cli_version: &Version) -> Vec<String> {
    let registry = get_attest_arg_registry();
    let base_version = Version::new(
        scone_cli_version.major,
        scone_cli_version.minor,
        scone_cli_version.patch,
    );
    let mut out = Vec::with_capacity(args.len());
    for arg in args {
        if let Some(entry) = registry.iter().find(|e| e.flag == arg.as_str()) {
            if entry.supported.matches(&base_version) {
                out.push(arg);
            } else {
                warn!(
                    "Dropping attest arg '{arg}' — not supported by Scone CLI {scone_cli_version}"
                );
            }
        } else {
            out.push(arg);
        }
    }
    out
}

fn contains_version_gated_arg(other_args: &[String]) -> bool {
    other_args.iter().any(|a| {
        get_attest_arg_registry()
            .iter()
            .any(|e| e.flag == a.as_str())
    })
}

pub struct SconeCli;

impl SconeCli {
    pub fn version() -> anyhow::Result<Version> {
        let args = vec!["--version".to_string()];
        let output =
            Self::try_execute_scone_cli(&args, Vec::<(&str, &str)>::new(), "31045-9872-4516")?;
        let word = output
            .split_whitespace()
            .last()
            .with_context(|| format!("Unexpected empty output from scone --version: '{output}'"))?;
        Version::parse(word).with_context(|| {
            format!("Could not parse Scone CLI version: '{word}' is not a valid semver")
        })
    }

    fn try_execute_scone_cli<S: AsRef<str>>(
        args: &[String],
        env: impl IntoIterator<Item = (S, S)>,
        error_code: &str,
    ) -> anyhow::Result<String> {
        let SconeCliCommandResult {
            exit_code,
            stdout,
            stderr,
        } = execute_scone_cli(args, env, vec!["SCONE_CONFIG_ID"]);
        if exit_code != 0 {
            bail!("Scone CLI command failed (ERROR {error_code}): {stderr}");
        }
        Ok(stdout)
    }

    pub fn retrieve_signer() -> anyhow::Result<String> {
        debug!("Determining the signer identity");
        let args = vec!["self".to_string(), "show-session-signing-key".to_string()];
        let stdout =
            Self::try_execute_scone_cli(&args, Vec::<(&str, &str)>::new(), "9808-322-4776")?;
        Ok(stdout.trim().to_string())
    }

    pub fn cas_attest(
        scone_cas_addr: &str,
        ignore_signer: bool,
        other_args: Vec<String>,
    ) -> anyhow::Result<String> {
        let other_args = if contains_version_gated_arg(&other_args) {
            let scone_cli_version = Self::version()?;
            filter_args_for_scone_cli(other_args, &scone_cli_version)
        } else {
            other_args
        };

        if ignore_signer {
            debug!("Attesting CAS {scone_cas_addr} without signer");
            let mut args = vec![
                "cas".to_string(),
                "attest".to_string(),
                scone_cas_addr.to_string(),
                "--only_for_testing-ignore-signer".to_string(),
            ];
            args.extend(other_args);
            return Self::try_execute_scone_cli(
                &args,
                Vec::<(&str, &str)>::new(),
                "1573-25311-11120",
            );
        }

        debug!("Attesting CAS {scone_cas_addr} with signer {K_MRSIGNER_DB}");
        let mut args = vec![
            "cas".to_string(),
            "attest".to_string(),
            scone_cas_addr.to_string(),
            "--mrsigner".to_string(),
            K_MRSIGNER_DB.to_string(),
        ];
        args.extend(other_args);
        Self::try_execute_scone_cli(&args, Vec::<(&str, &str)>::new(), "7520-30768-31405")
    }

    pub fn sign_cas_policy(
        cas_policy_file_name: &str,
        dest: OutputDest,
    ) -> anyhow::Result<PersistedFile> {
        debug!("Signing CAS policy {cas_policy_file_name}");
        let args = vec![
            "session".to_string(),
            "sign".to_string(),
            cas_policy_file_name.to_string(),
        ];
        let stdout =
            Self::try_execute_scone_cli(&args, Vec::<(&str, &str)>::new(), "28666-19528-6399")?;

        write_to_dest(&dest, stdout.as_bytes())
    }

    pub fn encrypt_cas_policy(
        cas_policy_file_name: &str,
        cas_addr: &str,
        dest: OutputDest,
    ) -> anyhow::Result<PersistedFile> {
        debug!("Encrypting CAS policy {cas_policy_file_name}");
        let args = vec![
            "session".to_string(),
            "encrypt".to_string(),
            cas_policy_file_name.to_string(),
            "--cas".to_string(),
            cas_addr.to_string(),
        ];
        let stdout =
            Self::try_execute_scone_cli(&args, Vec::<(&str, &str)>::new(), "9918-20782-3163")?;

        write_to_dest(&dest, stdout.as_bytes())
    }

    pub fn read_cas_policy_from_name(
        policy_name: &str,
        scone_cas_addr: &str,
    ) -> anyhow::Result<String> {
        info!("Reading session ({policy_name}) from cas at {scone_cas_addr}");
        let args = vec![
            "session".to_string(),
            "read".to_string(),
            "--cas".to_string(),
            scone_cas_addr.to_string(),
            policy_name.to_string(),
        ];
        let stdout =
            Self::try_execute_scone_cli(&args, Vec::<(&str, &str)>::new(), "129012-1221-72811")?;
        Ok(stdout)
    }

    pub fn calculate_session_hash_from_file<P: AsRef<Path>>(
        policy_file_path: P,
    ) -> anyhow::Result<String> {
        let path_ref = policy_file_path.as_ref();
        debug!("Calculating session hash of {:?}", path_ref);

        let args = vec![
            "session".to_string(),
            "calculate-hash".to_string(),
            path_ref.to_string_lossy().into_owned(),
        ];

        let stdout =
            Self::try_execute_scone_cli(&args, Vec::<(&str, &str)>::new(), "19175-9146-3013")?;
        Ok(stdout.trim().to_owned())
    }

    pub fn calculate_session_hash_from_content(
        policy_content: impl AsRef<[u8]>,
    ) -> anyhow::Result<String> {
        debug!("Calculating session hash from policy content");

        let mut tmp_policy_file = NamedTempFile::new()?;
        tmp_policy_file.write_all(policy_content.as_ref())?;

        tmp_policy_file.flush()?;

        let filename = tmp_policy_file.path().to_string_lossy();
        Self::calculate_session_hash_from_file(filename.as_ref())
    }
    pub fn scone_cas_show_identification(
        arg: Option<&str>,
        cas_address: &str,
    ) -> anyhow::Result<String> {
        let mut args = vec!["cas".to_string(), "show-identification".to_string()];
        if let Some(a) = arg {
            args.push(a.to_string());
        }
        args.push(cas_address.to_string());
        let stdout =
            Self::try_execute_scone_cli(&args, Vec::<(&str, &str)>::new(), "6621-27685-4998")?;
        Ok(stdout.trim().to_string())
    }

    pub fn cas_attest_with_offline_report(
        scone_cas_addr: &str,
        dcap_report_json: &str,
        nonce: &str,
        ignore_signer: bool,
        other_args: Vec<String>,
    ) -> anyhow::Result<String> {
        let mut more_args = vec![
            "--nonce".to_string(),
            nonce.to_string(),
            "--offline-report".to_string(),
            dcap_report_json.to_string(),
        ];
        more_args.extend(other_args);
        Self::cas_attest(scone_cas_addr, ignore_signer, more_args)
    }

    pub fn execute_scone_session_command(args: &[String]) -> Result<String, SconeCliCommandResult> {
        let mut full_args = vec!["session".to_string()];
        full_args.extend_from_slice(args);
        run_scone_command(&full_args, "16096-6804-19408")
    }

    pub fn execute_scone_command(args: &[String]) -> Result<String, SconeCliCommandResult> {
        run_scone_command(args, "27785-7589-20705")
    }

    pub fn execute_scone_cas_command(args: &[String]) -> Result<String, SconeCliCommandResult> {
        let mut full_args = vec!["cas".to_string()];
        full_args.extend_from_slice(args);
        run_scone_command(&full_args, "30503-16074-21257")
    }
}

fn run_scone_command(args: &[String], error_code: &str) -> Result<String, SconeCliCommandResult> {
    let SconeCliCommandResult {
        exit_code,
        stdout,
        mut stderr,
    } = execute_scone_cli(args, Vec::<(&str, &str)>::new(), ["SCONE_CONFIG_ID"]);
    if exit_code != 0 {
        stderr = format!(
            "Scone CLI command '{SCONECLI_BINARY} {}' failed (ERROR {error_code}): \n{stderr}",
            args.join(" ")
        );
        Err(SconeCliCommandResult {
            exit_code,
            stdout,
            stderr,
        })
    } else {
        Ok(stdout)
    }
}

#[cfg(test)]
mod tests {
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
}
