use handlebars::Handlebars;
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
        Err(_err) => format!("registry.scontain.com:5050/sconectl"),
    };

    let vol = match env::var("DOCKER_HOST") {
        Ok(val) => {
            let vol = val.strip_prefix("unix://").unwrap_or(&val).to_string();
            format!(r#"-e DOCKER_HOST="{val}" -v "{vol}":"{vol}""#)
        }
        Err(_e) => format!("-v /var/run/docker.sock:/var/run/docker.sock"),
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

/// Macro to execute the given command using the Posix Shell.
///
#[macro_export]
macro_rules! scone {
    ( $( $cmd:tt )* ) => {{
        $crate::execute_scone_cli("sh", &format!($( $cmd )*))
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
    fs::create_dir_all(tmp_session_dir).expect(&format!("Failed to create  directory '{tmp_session_dir}' for session files (Error 25235-11010-6922)"));

    if hash.is_empty() || force {
        info!("Hash for session {} empty. Trying to determine hash.", name);
        // we access the state object via a json "proxy" object
        // - we can access fields without needing to traits... but more importantly, this enables to create session for different fields
        let mut j: Value = serde_json::from_str(
            &serde_json::to_string_pretty(&state)
                .expect("Error serializing internal state (Error 1246-28944-24836)"),
        )
        .expect("Error parsing session state (Error 2213-735-18099)");

        let tmp_name = format!("{tmp_session_dir}/{}", random_name(20));
        let (code, stdout, stderr) = scone!("scone session read {} > {}", name, tmp_name);
        let mut do_create = force; // create session, if force is set
        let mut r = Err("Incorrect code");
        if code == 0 {
            info!("Got session {} .. verifying session now ", name);
            let (code, stdout, stderr) = scone!("scone session verify {}", tmp_name);
            let _ = fs::remove_file(tmp_name);
            if code == 0 {
                info!(
                    "OK: verified  session {}: predecessor='{}'",
                    name,
                    stdout.clone()
                );
                j["predecessor_key"] = "predecessor".into();
                j["predecessor"] = stdout.clone().into();
            } else {
                error!("Error verifying session {}: {} {}", name, stdout, stderr);
                return Err("Error reading session.");
            }
            r = Ok(stdout);
        } else {
            let _ = fs::remove_file(tmp_name);
            do_create = true; // create session, if we cannot read session - might not yet exist
            info!(
                "Reading of session {} failed! Trying to create session. {} {}",
                name, stdout, stderr
            );
            j["predecessor_key"] = "predecessor".into();
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
                let _rendered = reg
                    .render_template_to_write(template, &j, f)
                    .expect("error rendering template (Error 5164-30338-3399)");
            }
            let (code, stdout, stderr) = scone!("scone session check {}", &filename);
            if code != 0 {
                error!(
                    "Session {}: description in '{}' contains errors: {}",
                    &filename, name, stderr
                );
                // let _ = fs::remove_file(&filename);
                return Err("Session template seems to be incorrect - have a look at file.");
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
                r = Err("failed to create session.")
            }
        }
        r
    } else {
        Ok(hash.to_string())
    }
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
