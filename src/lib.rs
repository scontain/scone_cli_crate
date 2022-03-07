use log::{info,error};
use serde_json::{Value};
use serde::{Deserialize, Serialize};
use handlebars::Handlebars;
use shells::{sh};
use std::fs::OpenOptions;
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;
use std::fs;
use std::io;
use std::io::Write;

pub fn execute_with_docker(shell: &str, cmd: &str) -> (i32, String, String) {
    let w_prefix = &format!(r#"docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$HOME/.docker:/root/.docker" -v "$HOME/.cas:/root/.cas" -v "$HOME/.scone:/root/.scone" -v "$PWD:/root"     -w /root     registry.scontain.com:5050/sconecuratedimages/sconecli {}"#, cmd);
    let mut command = {
        let mut command = ::std::process::Command::new(shell);
        command.arg("-c").arg(w_prefix);
        command
    };

    match command.output() {
        Ok(output) => {
            (output.status.code().unwrap_or(if output.status.success() { 0 } else { 1 }),
             String::from_utf8_lossy(&output.stdout[..]).into_owned(),
             String::from_utf8_lossy(&output.stderr[..]).into_owned())
        },

        Err(e) => (126, String::new(), e.to_string()),
    }
}

/// Macro to execute the given command using the Posix Shell.
///
#[macro_export]
macro_rules! scone {
    ( $( $cmd:tt )* ) => {{
        $crate::execute_with_docker("sh", &format!($( $cmd )*))
    }};
}


pub fn create_session<'a, T : Serialize + for<'de> Deserialize<'de>>(name : &str, hash: &str, template: &str, state : &T, force: bool) -> Result<String, &'static str> {
    // if we already know the hash of the session, we do not try to create
    // unless we set flag force
    if hash.is_empty() || force {
        info!("Hash for session {} empty. Trying to determine hash.", name);
        // we access the state object via a json "proxy" object  
        // - we can access fields without needing to traits... but more importantly, this enables to create session for different fields
        let mut j : Value = serde_json::from_str(&serde_json::to_string_pretty(&state).expect("Error serializing internal state")).unwrap();

        let tmp_name = random_name(20);
        let (code,stdout, stderr) = scone!("scone session read {} > {}", name, tmp_name);
        let mut do_create = force; // create session, if force is set
        let mut r = Err("Incorrect code");
        if code == 0 {
            info!("Got session {} .. verifying session now ", name);
            let (code,stdout, stderr) = scone!("scone session verify {}", tmp_name);
            let _ = fs::remove_file(tmp_name);
            if code == 0 {
                info!("OK: verified  session {}", name);
                j["predecessor_key"] = "predecessor".into();
                j["predecessor"] = stdout.clone().into();
            } else {
                error!("Error verifying session {}: {} {}", name, stdout, stderr);
                return Err("Error reading session.")
            }
            r = Ok(stdout);
        } else {
            let _ = fs::remove_file(tmp_name);
            do_create = true; // create session, if we cannot read session - might not yet exist
            info!("Reading of session {} failed! Trying to create session. {} {}", name, stdout, stderr);
            j["predecessor_key"] = "#".into();
            j["predecessor"] = "".into();
        };
        if do_create {
            let mut reg = Handlebars::new();
            reg.set_strict_mode(true);
            let filename = random_name(20);
            {
                let f = OpenOptions::new().write(true).truncate(true).create(true).open(&filename).expect("Unable to open file");

                // create session from session template and check if correct
                let _rendered = reg.render_template_to_write(template, &j, f).expect("error rendering template");
            }
            let (code, _stdout, stderr) = scone!("scone session check {}", &filename);
            if code != 0 {
                error!("Session {}: description in '{}' contains errors: {}", &filename, name, stderr);
                // let _ = fs::remove_file(&filename);
                return Err("Session template seems to be incorrect - have a look at file.");
            }
            info!("Session template for {}: is correct.", name);

            // try to create / update the session
            let (code,stdout, stderr) = scone!("scone session create {}", &filename);
            let _ = fs::remove_file(&filename);
            if code == 0 {
                info!("Created session {}: {}", name, stdout);
                r = Ok(stdout);
            } else {
                info!("Creation of session {} failed: {} - see file {}", name, stderr, &filename);
                r = Err("failed to create session.")
            }
        }
        r
    } else {
        Ok(hash.to_string())
    }
}

pub fn to_json_value<T : Serialize> (o : T) -> serde_json::Value {
   let r : Value = serde_json::from_str(&serde_json::to_string_pretty(&o).expect("Error serializing Object")).expect("Error transformin to json object");
   r
}

//fn fromJsonValue<T : Serialize> (o : serde_json::Value) -> T {
//    let state : T  = serde_json::from_value(&o).expect("Cannot deserialize object");
//    state
//}
 
pub fn check_mrenclave<'a, T : Serialize + for<'de> Deserialize<'de>> (state: &mut T, mrenclave: &str, image: &str, binary: &str, force: bool) -> Result<(), &'static str> {
    let mut j : Value = to_json_value(&state);

    if j[mrenclave] == "" || force {
        let (code,stdout,stderr)=sh!(r#"docker run --rm -e SCONE_HASH=1 {} {} | tr -d '[:space:]'"#, j[image], j[binary]);
        if code == 0 {
            info!("MrEnclave = {}, stderr={}", stdout, stderr);
            j[mrenclave] = stdout.into();
            *state = serde_json::from_value(j).expect("deserialization");
            Ok(())
        } else {
            error!("Failed to determine MRENCLAVE: {}", stderr);
            Err("Failed to determine MrEnclave")
        }
    } else {
        Ok(())
    }
}


pub trait Init {
    fn new() -> Self;
}

pub fn write_state<T: Serialize>(state : &T, filename : &str) {
    let state = serde_json::to_string_pretty(&state).expect("Error serializing internal state");
    info!("writing state {}", state);
    fs::write(filename, state).unwrap_or_else(|_| panic!("Unable to write file '{}'", filename));
}

pub fn read_state<T: Init + for<'de> Deserialize<'de>>(filename : &str) -> T {
    if let Ok(state) = fs::read_to_string(filename) {
        info!("Read state {} from {}", state, filename);
        let state : T  = serde_json::from_str(&state).unwrap_or_else(|_| panic!("Cannot deserialize '{}'", filename));
        state
    } else {
        info!("Failed to read state from file {}: creating this file now.", filename);
        T::new()
    }
}

pub fn random_name(len : usize) -> String {
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
        io::stdout().flush().unwrap();
        let mut otp = String::new();
        io::stdin().read_line(&mut otp).expect("Error getting OTP");
        otp.retain(|c| !c.is_whitespace());
        otp
    }
}