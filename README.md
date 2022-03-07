# SCONE CLI Crate

We have often similar tasks to manage confidential applications:

- we need to create namespaces
- we need to create sessions
- we need to update namespaces / sessions
- ...

Often, very similar tasks need to be addressed in the context of different projects.
We defined a Rust crate that simplifies solving these repetitive tasks. The functions defined
in this crate are related to the SCONE CLI. Underneath the hood it uses the [SCONE CLI](https://sconedocs.github.io/CAS_cli/).

## Usage

You can use this crate in the context of Rust programs and Rust-scripts. You can view some 
examples in the context of, for example, section OTP.

## Functions

This crate implements the following functions and macros:

- `scone!`: execute a command in the scone cli container image.The assumption is that we have access to `docker` to run the command.
- `create_session`: checks if a session exists and creates or updates a session if needed
- `check_mrenclave`: computes `MRENCLAVE` of given container image / binary.
- `write_state`: writes out a state object to a file
- `read_state`: reads a state object from a file

Soon, we will add more functions to address other recurring tasks.

## Commands

- **gen_template**:
  - 
  - generate default template - modify this if needed
- **create_policy**: generate
- **AddAuthenticator**:
- **GenQRCode**:


- Commands::Create{ force, verbose } => { init_logger(verbose); create_command(force) },
  Commands::AddAuthenticator{ ootp, verbose } => { init_logger(verbose); add_authenticator(ootp) },
  Commands::GenQRCode{ verbose } => { init_logger(verbose); gen_qr_code() },
  Commands::TestQRCode{ verbose } => { init_logger(verbose); test_qr_code() },
  Commands::RollForward{ force, verbose } => { init_logger(verbose); roll_forward(force) },
