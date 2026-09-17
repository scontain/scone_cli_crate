//! The one interface behind every SCONE CLI backend.
//!
//! Two crates implement it:
//!
//! * `scone_cli_crate`  – open source, runs the `scone` binary and parses what it prints.
//! * `scone_cli_as_lib` – private, calls the SCONE implementation in-process.
//!
//! Both crates `pub use scone_cli_api::*` and provide a `SconeCli` type that implements
//! [`SconeCliApi`], so an application only ever depends on *one* of them and picks it with a
//! single `cfg` line:
//!
//! ```ignore
//! #[cfg(feature = "scone-private")] use scone_cli_as_lib as scone;
//! #[cfg(feature = "scone-public")]  use scone_cli_crate  as scone;
//!
//! use scone::{SconeCli, SconeCliApi};
//! let cli = SconeCli::with_config("/data/owner/config.json");
//! let signing_key = cli.session_signing_public_key()?;
//! ```
//!
//! Because request/response types live here and the method list is a trait, "both crates have the
//! same interface" is enforced by the compiler instead of by discipline.
//!
//! All operations are **blocking**. Call them from `spawn_blocking` when inside async code.

mod api;
mod types;

pub use api::SconeCliApi;
pub use types::{
    AttestationSettings, AttestationSource, AuditLogRequest, CasAddress, CasAttestRequest,
    CasIdentityKeys, CasProvisionRequest, CheckpointsRequest, CommandOutput, K_MRSIGNER_DB,
};

#[cfg(test)]
mod tests;
