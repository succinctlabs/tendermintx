//! To build the binary:
//!
//!     `cargo build --release --bin skip`
//!
//! To build the circuit:
//!
//!     `./target/release/circuit_function_field build`
//!
//! To prove the circuit using evm io:
//!
//!    `./target/release/circuit_function_evm prove --input-json src/bin/circuit_function_evm_input.json`
//!
//! Note that this circuit will not work with field-based io.
//!
//!
//!
//!
use std::env;

use plonky2x::backend::function::Plonky2xFunction;
use zk_tendermint::skip::SkipCircuit;

fn main() {
    let env_validator_set_size_max = env::var("VALIDATOR_SET_SIZE_MAX").unwrap_or(0.to_string());

    if env_validator_set_size_max == 128.to_string() {
        const VALIDATOR_SET_SIZE_MAX: usize = 128;
        SkipCircuit::<VALIDATOR_SET_SIZE_MAX>::entrypoint();
    } else if env_validator_set_size_max == 32.to_string() {
        const VALIDATOR_SET_SIZE_MAX: usize = 32;
        SkipCircuit::<VALIDATOR_SET_SIZE_MAX>::entrypoint();
    } else if env_validator_set_size_max == 4.to_string() {
        const VALIDATOR_SET_SIZE_MAX: usize = 4;
        SkipCircuit::<VALIDATOR_SET_SIZE_MAX>::entrypoint();
    } else {
        panic!("VALIDATOR_SET_SIZE_MAX must be set to 128, 32 or 4");
    }
}
