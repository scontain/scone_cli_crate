use handlebars::Handlebars;
use handlebars::JsonValue;
use log::{error, info};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use shells::sh;
use std::env;
use std::fs;
use std::fs::OpenOptions;
use std::io;
use std::io::Write;
use std::path::Path;

pub fn is_running_in_container() -> bool {
    // podman create /run/.containerenv inside containers
    // https://github.com/containers/podman/blob/main/docs/source/markdown/podman-run.1.md.in
    Path::new("/.dockerenv").exists() || Path::new("/run/.containerenv").exists()
}

pub fn execute_scone_cli(shell: &str, cmd: &str) -> (i32, String, String) {
    let repo = match env::var("SCONECTL_REPO") {
        Ok(repo) => repo,
        Err(_err) => "registry.scontain.com/sconectl".to_string(),
    };

    let vol = match env::var("DOCKER_HOST") {
        Ok(val) => {
            let vol = val.strip_prefix("unix://").unwrap_or(&val).to_string();
            format!(r#"-e DOCKER_HOST="{val}" -v "{vol}":"{vol}""#)
        }
        Err(_e) => "-v /var/run/docker.sock:/var/run/docker.sock".to_string(),
    };

    let mut w_prefix = format!(
        r#"docker run --entrypoint="" -e "SCONECTL_REPO={repo}" --rm {vol} -v "$HOME/.docker:/root/.docker" -v "$HOME/.cas:/root/.cas" -v "$HOME/.scone:/root/.scone" -v "$PWD:/wd" -w /wd  {repo}/sconecli:latest  {cmd}"#
    );

    // we speed up calls if we already running inside of a container!
    if is_running_in_container() {
        w_prefix = cmd.to_string();
    }
    let mut command = {
        let mut command = ::std::process::Command::new(shell);
        command.arg("-c").arg(w_prefix);
        command
    };

    match command.output() {
        Ok(output) => (
            output
                .status
                .code()
                .unwrap_or(if output.status.success() { 0 } else { 1 }),
            String::from_utf8_lossy(&output.stdout[..]).into_owned(),
            String::from_utf8_lossy(&output.stderr[..]).into_owned(),
        ),

        Err(e) => (126, String::new(), e.to_string()),
    }
}

#[macro_export]
macro_rules! scone {
    ( $( $cmd:tt )* ) => {{
        $crate::execute_scone_cli("sh", &format!($( $cmd )*))
    }};
}

pub fn execute_local(shell: &str, cmd: &str) -> (i32, String, String) {
    let mut command = {
        let mut command = ::std::process::Command::new(shell);
        command.arg("-c").arg(cmd.to_string());
        command
    };

    match command.output() {
        Ok(output) => (
            output
                .status
                .code()
                .unwrap_or(if output.status.success() { 0 } else { 1 }),
            String::from_utf8_lossy(&output.stdout[..]).into_owned(),
            String::from_utf8_lossy(&output.stderr[..]).into_owned(),
        ),

        Err(e) => (126, String::new(), e.to_string()),
    }
}

/// Macro to execute the given command using the Posix Shell.
///
#[macro_export]
macro_rules! local {
    ( $( $cmd:tt )* ) => {{
        $crate::execute_local("sh", &format!($( $cmd )*))
    }};
}

pub fn create_session<'a, T: Serialize + for<'de> Deserialize<'de>>(
    name: &str,
    hash: &str,
    template: &str,
    state: &T,
    force: bool,
) -> Result<String, &'static str> {
    // if we already know the hash of the session, we do not try to create
    // unless we set flag force

    let tmp_session_dir = "target/session_files";
    fs::create_dir_all(tmp_session_dir).unwrap_or_else(|_| panic!("Failed to create  directory '{tmp_session_dir}' for session files (Error 25235-11010-6922)"));

    if hash.is_empty() || force {
        info!("Hash for session {} empty. Trying to determine hash.", name);
        // we access the state object via a json "proxy" object
        // - we can access fields without needing to traits... but more importantly, this enables to create session for different fields
        let mut j: Value = serde_json::from_str(
            &serde_json::to_string_pretty(&state)
                .expect("Error serializing internal state (Error 1246-28944-24836)"),
        )
        .expect("Error parsing session state (Error 2213-735-18099)");
        j["CREATOR"] = "CREATOR".into();

        let tmp_name = format!("{tmp_session_dir}/{}", random_name(20));
        let (code, stdout, stderr) = scone!("scone session read {} > {}", name, tmp_name);
        let mut do_create = force; // create session, if force is set
        let mut r = Err("Incorrect code (Error 20336-4334-9699)");
        if code == 0 {
            info!("Got session {} .. verifying session now ", name);
            let (code, stdout, stderr) = scone!("scone session verify {}", tmp_name);
            let _ = fs::remove_file(tmp_name);
            if code == 0 {
                info!("OK: verified  session {}: predecessor='{}'", name, stdout);
                j["predecessor"] = stdout.clone().into();
            } else {
                error!("Error verifying session {}: {} {}", name, stdout, stderr);
                return Err("Error reading session. (Error 28030-29956-32283)");
            }
            r = Ok(stdout);
        } else {
            let _ = fs::remove_file(tmp_name);
            do_create = true; // create session, if we cannot read session - might not yet exist
            info!(
                "Reading of session {} failed! Trying to create session. {} {}",
                name, stdout, stderr
            );
            j["predecessor"] = "~".into();
        };
        if do_create {
            let mut reg = Handlebars::new();
            reg.set_strict_mode(true);
            let filename = format!("{tmp_session_dir}/{}", random_name(20));
            {
                let f = OpenOptions::new()
                    .write(true)
                    .truncate(true)
                    .create(true)
                    .open(&filename)
                    .expect("Unable to open file '{filename}' (Error 23526-16225-1902)");
                info!("session template={template}");
                // create session from session template and check if correct
                reg.render_template_to_write(template, &j, f)
                    .expect("error rendering template (Error 5164-11338-3399)");
            }
            let (code, stdout, stderr) = scone!("scone session check {}", &filename);
            if code != 0 {
                error!(
                    "Session {}: description in '{}' contains errors: {}",
                    &filename, name, stderr
                );
                // let _ = fs::remove_file(&filename);
                return Err("Session template seems to be incorrect - have a look at file. (Error 32608-18428-12247)");
            }
            info!("Session template for {}: is correct: {}", name, stdout);

            // try to create / update the session
            let (code, stdout, stderr) = scone!("scone session create {}", &filename);
            // let _ = fs::remove_file(&filename);
            if code == 0 {
                info!("Created session {}: {}", name, stdout);
                r = Ok(stdout);
            } else {
                info!(
                    "Creation of session {} failed: {} - see file {}",
                    name, stderr, &filename
                );
                r = Err("failed to create session. (Error 8583-25322-21167)")
            }
        }
        r
    } else {
        Ok(hash.to_string())
    }
}

use opg::*;

#[derive(Debug, PartialEq, Serialize, Clone, OpgModel, Deserialize, Copy)]
pub enum PolicyHandling {
    #[opg(
        "By default, we upload a signed policy to the specified CAS via TLS_ The upload is performed with command `scone session create`. When encrypting sessions if `cas_key` was specified.",
        example = "Upload"
    )]
    Upload,
    #[opg(
        "We upload the signed manifest with `kubectl create`",
        example = "Sign"
    )]
    SignedManifest,
    #[opg(
        "We upload the encrypted manifest with `kubectl create`",
        example = "Encrypt"
    )]
    EncryptedManifest,
    #[opg(
        "We create signed and encrypted sessions and manifests. However, we do not upload any of these.",
        example = "NoUpload"
    )]
    NoUpload,
    #[opg(
        "We create encrypted sessions and manifests. All others are deleted. Encrypted sessions are not automatically uploaded. The manifest can be uploaded later with `kubectl`.",
        example = "EncryptedManifest"
    )]
    EncryptedOnly,
}

pub fn get_creator() -> String {
    info!("Determine the creator Identity");

    let (code, stdout, stderr) = scone!("scone self show-key-hash");
    if code == 0 {
        info!("creator identity:  {stdout}");
        stdout
    } else {
        error!("Error determining the creator identity:\nstdout:\n{stdout}\nstderr:\n{stderr}");
        panic!("Error determining the creator identity. (Error 11119-25109-32878)");
    }
}

pub fn get_signer() -> String {
    info!("Determine the signer identity");

    let (code, stdout, stderr) = scone!("scone self show-session-signing-key");
    if code == 0 {
        info!("creator signing identity:  {stdout}");
        stdout
    } else {
        error!(
            "Error determining the creator signing identity:\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
        panic!("Error determining creator signing identity. (Error 11119-25109-82392)");
    }
}

pub fn sign_encrypt_session<'a, T: Serialize + for<'de> Deserialize<'de>>(
    name: &str,
    _hash: &str,
    template: &str,
    state: &T,
    mode: PolicyHandling,
    encryption_key: &Option<String>,
    scone_cas_addr: &str,
    weight: i64,
) -> Result<String, &'static str> {
    // if we already know the hash of the session, we do not try to create
    // unless we set flag force

    let tmp_session_dir = "target/session_files";
    fs::create_dir_all(tmp_session_dir).unwrap_or_else(|_| panic!("Failed to create  directory '{tmp_session_dir}' for session files (Error 25235-11010-6922)"));
    let binding = str::replace(
        &str::replace(
            &str::replace(&str::replace(&name, "_", "-"), ":", "-"),
            "/",
            "-",
        ),
        ".",
        "-",
    );
    let out_fname = binding.trim_matches('"');
    let predecessor_fname = format!("{tmp_session_dir}/signed_{out_fname}.predecessor");

    let mut j: Value = serde_json::from_str(
        &serde_json::to_string_pretty(&state)
            .expect("Error serializing internal state (Error 1246-28944-24836)"),
    )
    .expect("Error parsing session state (Error 2213-735-18099)");

    // try to read existing session from filesystem and try to extract predecessor from this
    if let Ok(content) = fs::read_to_string(&predecessor_fname) {
        j["predecessor"] = serde_json::Value::String(content);
    } else {
        // otherwise: assume that this is a new policy to write
        j["predecessor"] = "~".into();
    }
    let signer = get_signer();
    let creator = get_creator();
    let session_creator = format!("signer: {signer}");
    j["CREATOR"] = serde_json::Value::String(creator.clone());
    j["SIGNER"] = serde_json::Value::String(signer.clone());
    j["SESSION_CREATOR"] = serde_json::Value::String(session_creator); // we always sign sessions: hence, the creator is the signer
    let mut reg = Handlebars::new();
    reg.set_strict_mode(true);
    let filename = format!("{tmp_session_dir}/{}", random_name(20));

    {
        let f = OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open(&filename)
            .expect("Unable to open file '{filename}' (Error 23526-16225-1902)");
        info!("session template={template}");
        // create session from session template and check if correct
        reg.render_template_to_write(template, &j, f)
            .expect("error rendering template (Error 5134-30338-3378)");
    }

    let (code, stdout, stderr) = scone!("scone session check {}", &filename);
    if code != 0 {
        error!(
            "Session {}: description in '{}' contains errors: {}",
            &filename, name, stderr
        );
        // let _ = fs::remove_file(&filename);
        return Err("Session template seems to be incorrect - have a look at file. (Error 18583-11027-29850)");
    }
    info!(
        "Session template for session {}: is correct: {}",
        name, stdout
    );

    use std::fs::File;

    // always sign session - no matter what
    let mut return_value;
    let session_json = format!("{tmp_session_dir}/signed_{out_fname}.json");
    let (code, _stdout, stderr) = scone!("scone session sign {filename} > {session_json}");
    if code == 0 {
        info!("Created session {name}: '{stderr}'");
        let _ = fs::remove_file(&filename);
        let (code, stdout, _stderr) =
            scone!("scone session calculate-hash {tmp_session_dir}/signed_{out_fname}.json");
        if code == 0 {
            info!("Session digest: '{stdout}' (stderr={stderr})");
            let mut f = File::create(&predecessor_fname)
                .expect("Failed to create predecessor file (Error 6283-22176-27631)");
            write!(f, "{stdout}")
                .expect("Failed to write predecessor (signed) (Error 356-626-21265)");
            return_value = Ok(stdout);
        } else {
            return Err("failed to determine session hash. (Error 1078-16432-19559)");
        }
    } else {
        info!("Signing of session {name} failed: {stderr} - see file {filename} (32923-49430-2382389)");
        return Err("failed to sign session. (Error 5540-3086-16296)");
    }
    let _ = fs::remove_file(&filename);

    // try to encrypt the session -- need CAS key
    let encrypted_session_json = format!("{tmp_session_dir}/encrypted_{out_fname}.json");
    if let Some(key) = encryption_key {
        let (code, stdout, stderr) =
            scone!("scone session encrypt --key {key} {session_json} > {encrypted_session_json}");
        if code == 0 {
            info!(
                "Created encrypted session {name} --key {key} - {encrypted_session_json}: {stdout}"
            );
        } else {
            info!("Failed to create encrypted session {name} failed: {stderr} - see file {session_json}");
            return Err("failed to encrypt session. (Error 29926-22481-2946)");
        }
    } else {
        // todo: check if we need to encrypt, i.e., mode requires encryption
        info!("No encryption key specified ... using key from CLI");
        let (code, stdout, stderr) =
            scone!("scone session encrypt {session_json} > {encrypted_session_json}");
        if code == 0 {
            info!("Created encrypted session {name} - {encrypted_session_json}: {stdout}");
        } else {
            info!("Failed to create encrypted session {name} failed: {stderr} - see file {session_json}");
            return Err("failed to encrypt session. (Error 29926-22481-23832)");
        }
    }

    // create signed manifests
    let policy: Value = if let Ok(content) = fs::read_to_string(&session_json) {
        if let Ok(policy) = serde_json::from_str(&content) {
            policy
        } else {
            info!("Failed to parse signed session {name} from file {session_json}");
            return Err("failed to read signed session. (Error 24175-5973-18109)");
        }
    } else {
        info!("Failed to read signed session {name} from file {session_json}");
        return Err("failed to read signed session. (Error 25390-21169-31176)");
    };

    let signed_session_manifest = format!("{tmp_session_dir}/signed_manifest_{out_fname}.yaml");
    let policy_content = &policy["session"];
    let signature = &policy["signatures"][0]["signature"];
    let manifest_template = format!(
        r#"
apiVersion: cas.scone.cloud/v1beta1
kind: SignedPolicy
metadata:
    name: {out_fname}
    annotations:
      "helm.sh/hook": "pre-install,pre-upgrade"
      "helm.sh/hook-weight": "{weight}"
spec:
  casAddress: https://{scone_cas_addr}:8081
  policy: {policy_content}
  signatures:
    - signer: {signer}
      signature: {signature}
"#
    );

    let mut f = File::create(&signed_session_manifest)
        .expect("Failed to create manifest file (Error 19234-20626-20326)");
    write!(f, "{manifest_template}")
        .expect("Failed to write signed manifest (Error 827-11069-14338)");

    // create encrypted manifest
    //    if let Some(key) = encryption_key  {
    let policy: Value = if let Ok(content) = fs::read_to_string(&encrypted_session_json) {
        if let Ok(policy) = serde_json::from_str(&content) {
            policy
        } else {
            info!("Failed to parse encrypted session {name} from file {encrypted_session_json}");
            return Err("failed to read signed session. (Error 24175-5973-18210)");
        }
    } else {
        info!("Failed to read encrypted session {name} from file {encrypted_session_json}");
        return Err("failed to read signed session. (Error 25390-21169-31286)");
    };

    let encrypted_session_manifest =
        format!("{tmp_session_dir}/encrypted_manifest_{out_fname}.yaml");
    let policy_content = &policy["encrypted_session"];
    let key = &policy["encryption_key"];

    // todo: make port of casAddress configurable
    let manifest_template = format!(
        r#"
apiVersion: cas.scone.cloud/v1beta1
kind: EncryptedPolicy
metadata:
    name: {out_fname}
    annotations:
      "helm.sh/hook": "pre-install,pre-upgrade"
      "helm.sh/hook-weight": "{weight}"
spec:
    casAddress: https://{scone_cas_addr}:8081
    policy: {policy_content}
    encryptionKey: {key}
"#
    );

    let mut f = File::create(&encrypted_session_manifest)
        .expect("Failed to create encrypted manifest file (Error 19234-20626-20427)");
    write!(f, "{manifest_template}")
        .expect("Failed to write encrypted manifest (Error 832-23323-14338)");

    // // check if we need to upload the session to CAS directly
    // if mode == PolicyHandling::EncryptedManifest {
    //     let (code, stdout, stderr) = local!("kubectl apply -f {encrypted_session_manifest}");
    //     if code == 0 {
    //         info!("Created encrypted session {name} with kubectl: {stdout}");
    //     } else {
    //         info!("ERROR: Creation of encrypted session {name} failed: {stderr} - see file {encrypted_session_manifest}");
    //         return_value = Err("failed to create session. (Error 11902-13469-4444)")
    //     }
    // }

    // check if we need to upload the session to CAS directly
    if mode == PolicyHandling::Upload {
        let (code, stdout, stderr) = scone!("scone session create {session_json}");
        if code == 0 {
            info!("Created session {name}: {stdout}");
        } else {
            info!("ERROR: Creation of session {name} failed: {stderr} - see file {session_json}");
            return_value = Err("failed to create session. (Error 11902-13469-3222)")
        }
    }

    // check if we need to upload the session to CAS directly
    if mode == PolicyHandling::SignedManifest {
        let (code, stdout, stderr) = local!("kubectl apply -f {signed_session_manifest}");
        if code == 0 {
            info!("Created signed session {name} with kubectl: {stdout}");
        } else {
            info!("ERROR: Creation of signed session {name} failed: {stderr} - see file {signed_session_manifest}");
            return_value = Err("failed to create session. (Error 11902-13469-3222)")
        }
    }

    return_value
}

pub fn to_json_value<T: Serialize>(o: T) -> serde_json::Value {
    let r: Value = serde_json::from_str(
        &serde_json::to_string_pretty(&o)
            .expect("Error serializing Object (Error 22405-15525-20124)"),
    )
    .expect("Error transforming to json object (Error 24639-23448-20309)");
    r
}

//fn fromJsonValue<T : Serialize> (o : serde_json::Value) -> T {
//    let state : T  = serde_json::from_value(&o).expect("Cannot deserialize object");
//    state
//}

// todo: replace by determine_mrenclave
// bug: mrenclave is NOT set!

pub fn check_mrenclave<'a, T: Serialize + for<'de> Deserialize<'de>>(
    state: &mut T,
    mrenclave: &str,
    image: &str,
    binary: &str,
    force: bool,
) -> Result<(), &'static str> {
    let mut j: Value = to_json_value(&state);

    if j[mrenclave] == "" || force {
        let (code, stdout, stderr) = sh!(
            r#"docker run --entrypoint="" --rm -e SCONE_HASH=1 {} {} | tr -d '[:space:]'"#,
            j[image],
            j[binary]
        );
        if code == 0 {
            info!("MrEnclave = {}, stderr={}", stdout, stderr);
            j[mrenclave] = stdout.into();
            *state =
                serde_json::from_value(j).expect("deserialization failed (Error 25507-7831-3147)");
            Ok(())
        } else {
            error!(
                "Failed to determine MRENCLAVE: {} (Error 13231-21732-26347)",
                stderr
            );
            Err("Failed to determine MrEnclave (Error 16676-22493-8368)")
        }
    } else {
        Ok(())
    }
}

/// given a json state -> set MrEnclave
pub fn determine_mrenclave(
    state: &mut JsonValue,
    mrenclave: &str,
    image: &str,
    binary: &str,
) -> Result<(), &'static str> {
    let mut j: Value = to_json_value(&state);

    let (code, stdout, stderr) = sh!(
        r#"docker run --entrypoint="" --rm -e SCONE_HASH=1 {} {} | tr -d '[:space:]'"#,
        j[image],
        j[binary]
    );
    if code == 0 {
        info!("MrEnclave = {}, stderr={}", stdout, stderr);
        j[mrenclave] = stdout.into();
        *state = serde_json::from_value(j).expect("deserialization failed (Error 25507-7831-3147)");
        Ok(())
    } else {
        error!(
            "Failed to determine MRENCLAVE: {} (Error 13231-21732-26347)",
            stderr
        );
        Err("Failed to determine MrEnclave (Error 16676-22493-8368)")
    }
}

pub trait Init {
    fn new() -> Self;
}

pub fn write_state<T: Serialize>(state: &T, filename: &str) {
    let state = serde_json::to_string_pretty(&state)
        .expect("Error serializing internal state (Error 30804-13523-32231)");
    info!("writing state {}", state);
    fs::write(filename, state).unwrap_or_else(|_| {
        panic!(
            "Unable to write file '{}' (Error 8757-10881-14894)",
            filename
        )
    });
}

pub fn read_state<T: Init + for<'de> Deserialize<'de>>(filename: &str) -> T {
    if let Ok(state) = fs::read_to_string(filename) {
        info!("Read state {} from {}", state, filename);
        let state: T = serde_json::from_str(&state).unwrap_or_else(|_| {
            panic!("Cannot deserialize '{}' (Error 18692-11485-8949)", filename)
        });
        state
    } else {
        info!(
            "Failed to read state from file {}: creating this file now. (Warning 4384-20698-6487)",
            filename
        );
        T::new()
    }
}

pub fn random_name(len: usize) -> String {
    let rand_string: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect();
    rand_string
}

pub fn get_otp(otp: Option<String>) -> String {
    if let Some(otp) = otp {
        otp
    } else {
        let prompt = r#"
        Adding a new authenticate requires an OTP from an existing authenticator.
            - The new QR code is written to file 'qrcode.svg'
            - Starting containers can take some while. Hence, wait for a new QR code to appear on your authenticator.
        Type OTP and press enter: "#;

        print!("{}", prompt);

        // get OTP from user
        io::stdout()
            .flush()
            .expect("Error flushing stdout (Error 6759-25742-26859)");
        let mut otp = String::new();
        io::stdin()
            .read_line(&mut otp)
            .expect("Error getting OTP (Error 30189-22111-13542)");
        otp.retain(|c| !c.is_whitespace());
        otp
    }
}
