//! SCONE CLI access by running the `scone` binary.
//!
//! This crate implements [`SconeCliApi`] by translating each call into a `scone ...` command
//! line. `scone_cli_as_lib` implements the very same trait in-process, so an application can
//! switch between the two with one `cfg` line. See the `scone_cli_api` crate docs.

mod commands;
mod engine;
mod report;
mod runner;
mod session_file;
mod version_gate;

mod cli;

pub use cli::SconeCli;
pub use scone_cli_api::*;
