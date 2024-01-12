use std::marker::PhantomData;

use async_trait::async_trait;
use plonky2x::backend::circuit::Circuit;
use plonky2x::frontend::hint::asynchronous::hint::AsyncHint;
use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::frontend::vars::{ValueStream, Variable, VariableStream};
use plonky2x::prelude::{
    ArrayVariable, BoolVariable, Bytes32Variable, CircuitBuilder, Field, PlonkParameters,
};
use serde::{Deserialize, Serialize};

use crate::builder::verify::TendermintVerify;
use crate::config::TendermintConfig;
use crate::input::InputDataFetcher;
use crate::variables::*;

pub trait TendermintStepCircuit<L: PlonkParameters<D>, const D: usize> {
    fn step<const MAX_VALIDATOR_SET_SIZE: usize, const CHAIN_ID_SIZE_BYTES: usize>(
        &mut self,
        chain_id_bytes: &[u8],
        prev_block_number: U64Variable,
        prev_header_hash: Bytes32Variable,
    ) -> Bytes32Variable;
}

impl<L: PlonkParameters<D>, const D: usize> TendermintStepCircuit<L, D> for CircuitBuilder<L, D> {
    fn step<const MAX_VALIDATOR_SET_SIZE: usize, const CHAIN_ID_SIZE_BYTES: usize>(
        &mut self,
        chain_id_bytes: &[u8],
        prev_block_number: U64Variable,
        prev_header_hash: Bytes32Variable,
    ) -> Bytes32Variable {
        let mut input_stream = VariableStream::new();
        input_stream.write(&prev_block_number);
        input_stream.write(&prev_header_hash);
        let output_stream = self.async_hint(
            input_stream,
            StepOffchainInputs::<MAX_VALIDATOR_SET_SIZE> {},
        );
        let next_header = output_stream.read::<Bytes32Variable>(self);
        let round_present = output_stream.read::<BoolVariable>(self);
        let next_block_validators =
            output_stream.read::<ArrayVariable<ValidatorVariable, MAX_VALIDATOR_SET_SIZE>>(self);
        let nb_validators = output_stream.read::<Variable>(self);
        let next_block_chain_id_proof = output_stream.read::<ChainIdProofVariable>(self);
        let next_block_validators_hash_proof =
            output_stream.read::<HashInclusionProofVariable>(self);
        let next_block_last_block_id_proof =
            output_stream.read::<BlockIDInclusionProofVariable>(self);
        let prev_block_next_validators_hash_proof =
            output_stream.read::<HashInclusionProofVariable>(self);

        self.verify_step::<MAX_VALIDATOR_SET_SIZE, CHAIN_ID_SIZE_BYTES>(
            chain_id_bytes,
            &next_block_validators,
            nb_validators,
            &next_header,
            &prev_header_hash,
            &next_block_chain_id_proof,
            &next_block_validators_hash_proof,
            &prev_block_next_validators_hash_proof,
            &next_block_last_block_id_proof,
            &round_present,
        );
        next_header
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepOffchainInputs<const MAX_VALIDATOR_SET_SIZE: usize> {}

#[async_trait]
impl<const MAX_VALIDATOR_SET_SIZE: usize, L: PlonkParameters<D>, const D: usize> AsyncHint<L, D>
    for StepOffchainInputs<MAX_VALIDATOR_SET_SIZE>
{
    async fn hint(
        &self,
        input_stream: &mut ValueStream<L, D>,
        output_stream: &mut ValueStream<L, D>,
    ) {
        let prev_block_number = input_stream.read_value::<U64Variable>();
        let prev_header_hash = input_stream.read_value::<Bytes32Variable>();
        let mut data_fetcher = InputDataFetcher::default();
        let result = data_fetcher
            .get_step_inputs::<MAX_VALIDATOR_SET_SIZE, L::Field>(
                prev_block_number,
                prev_header_hash,
            )
            .await;

        output_stream.write_value::<Bytes32Variable>(result.next_header.into());
        output_stream.write_value::<BoolVariable>(result.round_present); // round_present
        output_stream.write_value::<ArrayVariable<ValidatorVariable, MAX_VALIDATOR_SET_SIZE>>(
            result.next_block_validators,
        );
        output_stream.write_value::<Variable>(L::Field::from_canonical_usize(result.nb_validators));
        output_stream.write_value::<ChainIdProofVariable>(result.next_block_chain_id_proof);
        output_stream
            .write_value::<HashInclusionProofVariable>(result.next_block_validators_hash_proof);
        output_stream
            .write_value::<BlockIDInclusionProofVariable>(result.next_block_last_block_id_proof);
        output_stream.write_value::<HashInclusionProofVariable>(
            result.prev_block_next_validators_hash_proof,
        );
    }
}

#[derive(Debug, Clone)]
pub struct StepCircuit<
    const MAX_VALIDATOR_SET_SIZE: usize,
    const CHAIN_ID_SIZE_BYTES: usize,
    C: TendermintConfig<CHAIN_ID_SIZE_BYTES>,
> {
    _config: PhantomData<C>,
}

impl<
        const MAX_VALIDATOR_SET_SIZE: usize,
        const CHAIN_ID_SIZE_BYTES: usize,
        C: TendermintConfig<CHAIN_ID_SIZE_BYTES>,
    > Circuit for StepCircuit<MAX_VALIDATOR_SET_SIZE, CHAIN_ID_SIZE_BYTES, C>
{
    fn define<L: PlonkParameters<D>, const D: usize>(builder: &mut CircuitBuilder<L, D>) {
        let prev_block_number = builder.evm_read::<U64Variable>();
        let prev_header_hash = builder.evm_read::<Bytes32Variable>();

        let next_header_hash = builder.step::<MAX_VALIDATOR_SET_SIZE, CHAIN_ID_SIZE_BYTES>(
            C::CHAIN_ID_BYTES,
            prev_block_number,
            prev_header_hash,
        );

        builder.evm_write(next_header_hash);
    }

    fn register_generators<L: PlonkParameters<D>, const D: usize>(
        generator_registry: &mut plonky2x::prelude::HintRegistry<L, D>,
    ) where
        <<L as PlonkParameters<D>>::Config as plonky2x::prelude::plonky2::plonk::config::GenericConfig<D>>::Hasher:
        plonky2x::prelude::plonky2::plonk::config::AlgebraicHasher<L::Field>,
    {
        generator_registry.register_async_hint::<StepOffchainInputs<MAX_VALIDATOR_SET_SIZE>>();
    }
}

#[cfg(test)]
mod tests {
    use std::env;

    use ethers::types::H256;
    use ethers::utils::hex;
    use plonky2x::backend::circuit::PublicInput;
    use plonky2x::prelude::{DefaultBuilder, GateRegistry, HintRegistry};

    use super::*;
    use crate::config::TendermintConfig;

    const CHAIN_ID_BYTES: &[u8] = b"mocha-4";
    const CHAIN_ID_SIZE_BYTES: usize = CHAIN_ID_BYTES.len();
    #[derive(Debug, Clone, PartialEq)]
    pub struct Mocha4Config;
    impl TendermintConfig<CHAIN_ID_SIZE_BYTES> for Mocha4Config {
        const CHAIN_ID_BYTES: &'static [u8] = CHAIN_ID_BYTES;
    }

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_step_serialization() {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        const MAX_VALIDATOR_SET_SIZE: usize = 2;
        let mut builder = DefaultBuilder::new();

        log::debug!("Defining circuit");
        StepCircuit::<MAX_VALIDATOR_SET_SIZE, CHAIN_ID_SIZE_BYTES, Mocha4Config>::define(
            &mut builder,
        );
        let circuit = builder.build();
        log::debug!("Done building circuit");

        let mut hint_registry = HintRegistry::new();
        let mut gate_registry = GateRegistry::new();
        StepCircuit::<MAX_VALIDATOR_SET_SIZE, CHAIN_ID_SIZE_BYTES, Mocha4Config>::register_generators(
            &mut hint_registry,
        );
        StepCircuit::<MAX_VALIDATOR_SET_SIZE, CHAIN_ID_SIZE_BYTES, Mocha4Config>::register_gates(
            &mut gate_registry,
        );

        circuit.test_serializers(&gate_registry, &hint_registry);
    }

    // This test should not run in CI because it uses the RPC instead of a fixture.
    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_step_circuit_with_input_bytes() {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        const MAX_VALIDATOR_SET_SIZE: usize = 4;
        // This is from block 3000 on Celestia mainet.
        let input_bytes = hex::decode(
            "0000000000000bb8a8512f18c34b70e1533cfd5aa04f251fcb0d7be56ec570051fbad9bdb9435e6a",
        )
        .unwrap();

        let mut builder = DefaultBuilder::new();

        log::debug!("Defining circuit");
        StepCircuit::<MAX_VALIDATOR_SET_SIZE, CHAIN_ID_SIZE_BYTES, Mocha4Config>::define(
            &mut builder,
        );

        log::debug!("Building circuit");
        let circuit = builder.build();
        log::debug!("Done building circuit");

        let input = PublicInput::Bytes(input_bytes);
        let (_proof, mut output) = circuit.prove(&input);
        let next_header = output.evm_read::<Bytes32Variable>();
        println!("next_header {:?}", next_header);
    }

    fn test_step_template<const MAX_VALIDATOR_SET_SIZE: usize>(
        block_height: u64,
        header: [u8; 32],
    ) {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        let mut builder = DefaultBuilder::new();

        log::debug!("Defining circuit");
        StepCircuit::<MAX_VALIDATOR_SET_SIZE, CHAIN_ID_SIZE_BYTES, Mocha4Config>::define(
            &mut builder,
        );

        log::debug!("Building circuit");
        let circuit = builder.build();
        log::debug!("Done building circuit");

        let mut input = circuit.input();
        input.evm_write::<U64Variable>(block_height);
        input.evm_write::<Bytes32Variable>(H256::from_slice(header.as_slice()));

        log::debug!("Generating proof");
        let (proof, mut output) = circuit.prove(&input);
        log::debug!("Done generating proof");

        circuit.verify(&proof, &input, &output);
        let next_header = output.evm_read::<Bytes32Variable>();
        println!("next_header {:?}", next_header);
    }

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_step_small() {
        const MAX_VALIDATOR_SET_SIZE: usize = 2;
        let header: [u8; 32] =
            hex::decode("A0123D5E4B8B8888A61F931EE2252D83568B97C223E0ECA9795B29B8BD8CBA2D")
                .unwrap()
                .try_into()
                .unwrap();
        let height = 10000u64;
        test_step_template::<MAX_VALIDATOR_SET_SIZE>(height, header);
    }

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_step_with_dummy() {
        const MAX_VALIDATOR_SET_SIZE: usize = 4;
        let header: [u8; 32] =
            hex::decode("E2BA1B86926925A69C2FCC32E5178E7E6653D386C956BB975142FA73211A9444")
                .unwrap()
                .try_into()
                .unwrap();
        let height = 10500u64;
        test_step_template::<MAX_VALIDATOR_SET_SIZE>(height, header);
    }

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_step_large() {
        const MAX_VALIDATOR_SET_SIZE: usize = 100;
        let header: [u8; 32] =
            hex::decode("E2BA1B86926925A69C2FCC32E5178E7E6653D386C956BB975142FA73211A9444")
                .unwrap()
                .try_into()
                .unwrap();
        let height = 10500u64;
        test_step_template::<MAX_VALIDATOR_SET_SIZE>(height, header);
    }
}
