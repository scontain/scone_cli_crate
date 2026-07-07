use log::{info, warn};
use spawn_server::{
    SpawnServerCommandResponse, run_local_exec, run_local_shell, srpc_exec, srpc_sh,
};
use std::env;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::process::Command;
use std::sync::{Mutex, OnceLock};

const DOCKER_NETWORK: &str = ""; // --network=host

pub const SCONECLI_BINARY: &str = "scone";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SconeCliCommandType {
    SpawnServerSconeCli,
    SpawnServerDocker,
    SconeCli,
    Docker,
    SpawnServer,
    None,
}

static SCONE_CLI_COMMAND_TYPE: OnceLock<SconeCliCommandType> = OnceLock::new();

pub fn get_scone_cli_command_type() -> &'static SconeCliCommandType {
    SCONE_CLI_COMMAND_TYPE.get_or_init(compute_scone_cli_command_type)
}

fn compute_scone_cli_command_type() -> SconeCliCommandType {
    info!("Determining how to execute the shell commands");

    let SpawnServerCommandResponse { exit_code, .. } = srpc_exec!(SCONECLI_BINARY, ["--version"]);

    if exit_code == 0 {
        info!("Both spawn_server and scone cli are installed");
        return SconeCliCommandType::SpawnServerSconeCli;
    }

    if exit_code == -1 {
        return if local_scone_installed() {
            info!("scone cli, but not spawn_server, is installed");
            SconeCliCommandType::SconeCli
        } else if local_docker_installed() {
            info!("docker, but neither scone cli nor spawn_server, is installed");
            SconeCliCommandType::Docker
        } else {
            info!("Neither spawn_server, docker, nor scone cli is installed");
            SconeCliCommandType::None
        };
    }

    if local_docker_installed() {
        info!("docker and spawn_server, but not scone cli, is installed");
        SconeCliCommandType::SpawnServerDocker
    } else {
        info!("spawn_server, but neither docker nor scone cli, is installed");
        SconeCliCommandType::SpawnServer
    }
}

pub fn local_scone_installed() -> bool {
    match Command::new(SCONECLI_BINARY).arg("--version").output() {
        Ok(out) => out.status.success(),
        Err(_) => false,
    }
}

pub fn local_docker_installed() -> bool {
    match Command::new("docker").arg("--version").output() {
        Ok(out) => out.status.success(),
        Err(_) => false,
    }
}

static VERSION: OnceLock<Mutex<String>> = OnceLock::new();

fn ensure_version() -> &'static Mutex<String> {
    VERSION.get_or_init(|| Mutex::new(String::from("latest")))
}

pub fn set_version<S: Into<String>>(version: S) {
    *ensure_version().lock().unwrap() = version.into();
}

pub fn get_version() -> String {
    ensure_version().lock().unwrap().clone()
}

#[derive(Clone, Debug)]
pub struct SconeCliCommandResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl From<SpawnServerCommandResponse> for SconeCliCommandResult {
    fn from(r: SpawnServerCommandResponse) -> Self {
        Self {
            exit_code: r.exit_code,
            stdout: r.stdout,
            stderr: r.stderr,
        }
    }
}

impl std::error::Error for SconeCliCommandResult {}

impl std::fmt::Display for SconeCliCommandResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "command exited with code {}", self.exit_code)?;
        if !self.stdout.is_empty() {
            write!(f, "\n  Standard Output:\n")?;
            for line in self.stdout.lines() {
                writeln!(f, "    {}", line)?;
            }
        }

        if !self.stderr.is_empty() {
            write!(f, "\n  Standard Error:\n")?;
            for line in self.stderr.lines() {
                writeln!(f, "    {}", line)?;
            }
        }
        Ok(())
    }
}

/// Execute a scone command.
///
/// - If `spawn_server` is installed, the binary is exec'd directly through
///   it (no shell).
/// - If `spawn_server` is unavailable but `scone` is installed locally, it is
///   exec'd directly via `std::process::Command`.
/// - If neither is available but `docker` is, the command runs inside a
///   docker container via a shell (needed for `$HOME`/`$(id -u)` expansion).
///   **`env_remove` has no effect on this path** -- a fresh container has no
///   inherited host env to remove in the first place, so anything in
///   `env_remove` is only logged, not acted on.
/// - Otherwise, this bails.
///
/// `args` should NOT include the binary name itself.
/// `env_remove` is applied before `env`, so a key present in both ends up
/// removed then re-set (i.e. `env` wins on conflicts).
pub fn execute_scone_cli<S, R>(
    args: &[String],
    env: impl IntoIterator<Item = (S, S)>,
    env_remove: impl IntoIterator<Item = R>,
) -> SconeCliCommandResult
where
    S: AsRef<str>,
    R: AsRef<str>,
{
    let env_vec: Vec<(String, String)> = env
        .into_iter()
        .map(|(k, v)| (k.as_ref().to_string(), v.as_ref().to_string()))
        .collect();
    let env_remove_vec: Vec<String> = env_remove
        .into_iter()
        .map(|k| k.as_ref().to_string())
        .collect();

    match *get_scone_cli_command_type() {
        SconeCliCommandType::SpawnServerSconeCli => {
            srpc_exec!(SCONECLI_BINARY, args.to_vec(), env_vec, env_remove_vec).into()
        }
        SconeCliCommandType::SpawnServerDocker => {
            if !env_remove_vec.is_empty() {
                warn!(
                    "env_remove ({:?}) is not necessary as No env var from the parent process is forwarded to the child process since we use docker (ERROR 15092-2233-1)",
                    env_remove_vec
                );
            }
            let docker_env = construct_docker_env(&env_vec);
            srpc_sh!(
                "{}",
                build_docker_command(SCONECLI_BINARY, args, &docker_env)
            )
            .into()
        }
        SconeCliCommandType::SconeCli => {
            run_local_exec(SCONECLI_BINARY, args, &env_vec, &env_remove_vec).into()
        }
        SconeCliCommandType::Docker => {
            if !env_remove_vec.is_empty() {
                warn!(
                    "env_remove ({:?}) is not necessary as No env var from the parent process is forwarded to the child process since we use docker (ERROR 15092-2233-1)",
                    env_remove_vec
                );
            }
            let docker_env = construct_docker_env(&env_vec);
            let full_command = build_docker_command(SCONECLI_BINARY, args, &docker_env);
            run_local_shell(&full_command).into()
        }
        SconeCliCommandType::SpawnServer | SconeCliCommandType::None => SconeCliCommandResult {
            exit_code: -3,
            stdout: String::new(),
            stderr: format!(
                "Failed to execute SCONE command '{SCONECLI_BINARY} {}': Neither '{SCONECLI_BINARY}' nor 'docker' is installed (ERROR 20154-13302-17922)",
                args.join(" ")
            ),
        },
    }
}

pub const DEBUG_SCONE_CLI_ENV: &[(&str, &str)] = &[
    ("SCONE_PRODUCTION", "0"),
    ("SCONE_NO_TIME_THREAD", "1"),
    ("SCONE_MODE", "sim"),
];

/// Executes a SCONE cli command in one of the supported modes.
///
/// # Examples
/// ```ignore
/// exec_scone!(debug, "cas", "list");
/// exec_scone!(production, "cas", "list");
/// exec_scone!(custom, env, "cas", "list");                       // env_remove defaults to []
/// exec_scone!(custom, env, remove ["SCONE_CONFIG_ID"], "cas", "list");
/// ```
#[macro_export]
macro_rules! exec_scone {
    (debug, $( $arg:expr ),+ $(,)?) => {{
        $crate::execute_scone_cli(
            &[$( $arg.to_string() ),+],
            $crate::DEBUG_SCONE_CLI_ENV.iter().copied(),
            Vec::<&str>::new(),
        )
    }};

    (production, $( $arg:expr ),+ $(,)?) => {{
        $crate::execute_scone_cli(
            &[$( $arg.to_string() ),+],
            Vec::<(&str, &str)>::new(),
            Vec::<&str>::new(),
        )
    }};

    (custom, $env:expr, remove $env_remove:expr, $( $arg:expr ),+ $(,)?) => {{
        $crate::execute_scone_cli(
            &[$( $arg.to_string() ),+],
            $env,
            $env_remove,
        )
    }};

    (custom, $env:expr, $( $arg:expr ),+ $(,)?) => {{
        $crate::execute_scone_cli(
            &[$( $arg.to_string() ),+],
            $env,
            Vec::<&str>::new(),
        )
    }};
}

/// Executes a SCONE cli command in production mode. See `exec_scone!()` for other modes.
#[macro_export]
macro_rules! scone {
    ( $( $arg:expr ),+ $(,)? ) => {{
        $crate::execute_scone_cli(
            $crate::SCONECLI_BINARY,
            &[$( $arg.to_string() ),+],
            Vec::<(&str, &str)>::new(),
            Vec::<&str>::new(),
        )
    }};
}

fn construct_docker_env(envs: &[(String, String)]) -> Vec<String> {
    let mut args = vec![];
    for (k, v) in envs {
        args.push("-e".to_string());
        args.push(format!("{k}={v}"));
    }
    args
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

fn build_docker_command(binary: &str, args: &[String], env_args: &[String]) -> String {
    let repo =
        env::var("SCONECTL_REPO").unwrap_or_else(|_| "registry.scontain.com/sconectl".to_string());

    let vol = match env::var("DOCKER_HOST") {
        Ok(val) => {
            if val.starts_with("unix://") {
                let vol = val.strip_prefix("unix://").unwrap_or(&val).to_string();
                format!(r#"-e DOCKER_HOST="{val}" -v "{vol}":"{vol}""#)
            } else if val.starts_with("tcp://") {
                warn!(
                    "Docker socket with TCP schema was detected. Will use DOCKER_HOST={val} to access docker socket inside container."
                );
                format!(r#"-e DOCKER_HOST="{val}""#)
            } else if val.parse::<Ipv4Addr>().is_ok() || val.parse::<SocketAddrV4>().is_ok() {
                warn!(
                    "IP address was detected. Will use DOCKER_HOST=tcp://{val} to access docker socket inside container."
                );
                format!(r#"-e DOCKER_HOST="tcp://{val}""#)
            } else {
                warn!("Docker socket: {} with unknown schema was detected.", val);
                r#"-e DOCKER_HOST=/var/run/docker.sock -v /var/run/docker.sock:/var/run/docker.sock"#.to_string()
            }
        }
        Err(_e) => "-v /var/run/docker.sock:/var/run/docker.sock".to_string(),
    };

    let env_vars_str = env_args.join(" ");
    let quoted_args: Vec<String> = args.iter().map(|a| shell_quote(a)).collect();
    let scone_command = format!("{binary} {}", quoted_args.join(" "));

    let docker_command = format!(
        r#"docker run --rm --platform linux/amd64 --add-host=host.docker.internal:host-gateway {DOCKER_NETWORK} {env_vars_str} --entrypoint="" -e "SCONECTL_REPO={repo}" {vol} -v "$HOME/.docker:/home/root/.docker" -v "$HOME/.cas:/home/nonroot/.cas" -v "$HOME/.scone:/home/nonroot/.scone" -v "$PWD:/wd" -w /wd --user $(id -u):$(id -g) --group-add $(getent group docker | cut -d: -f3)   {repo}/sconecli:{} sh -c '{scone_command}'"#,
        get_version()
    );
    info!("Executing: {docker_command}");
    docker_command
}
