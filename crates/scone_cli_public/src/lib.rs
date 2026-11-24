//! SCONE CLI access by running the `scone` binary.
//!
//! This crate implements [`SconeCliApi`] by translating each call into a `scone ...` command
//! line.

mod commands;
mod engine;
mod report;
mod runner;
mod session_file;
mod version_gate;

mod cli;

pub use cli::SconeCli;
pub use engine::{
    DEBUG_SCONE_CLI_ENV, SconeCliCommandResult, execute_scone_cli, set_scone_docker_version,
};
pub use scone_cli_api::*;
