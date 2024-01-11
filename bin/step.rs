//! To build the binary:
//!
//!     `cargo build --release --bin step`
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
use plonky2x::backend::function::Plonky2xFunction;
use tendermintx::config::TendermintConfig;
use tendermintx::consts::VALIDATOR_SET_SIZE_MAX;
use tendermintx::step::StepCircuit;

/// The chain ID of the Tendermint chain.
pub const CHAIN_ID_BYTES: &[u8] = b"celestia";
pub const CHAIN_ID_SIZE_BYTES: usize = CHAIN_ID_BYTES.len();
#[derive(Debug, Clone, PartialEq)]
pub struct CelestiaConfig;
impl TendermintConfig<CHAIN_ID_SIZE_BYTES> for CelestiaConfig {
    const CHAIN_ID_BYTES: &'static [u8] = CHAIN_ID_BYTES;
}

fn main() {
    StepCircuit::<VALIDATOR_SET_SIZE_MAX, CHAIN_ID_SIZE_BYTES, CelestiaConfig>::entrypoint();
}
