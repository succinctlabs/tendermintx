use std::fmt::Debug;
use std::marker::PhantomData;

use async_trait::async_trait;
use plonky2x::backend::circuit::Circuit;
use plonky2x::frontend::hint::asynchronous::hint::AsyncHint;
use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::frontend::vars::{ValueStream, VariableStream};
use plonky2x::prelude::{Bytes32Variable, CircuitBuilder, Field, PlonkParameters};
use serde::{Deserialize, Serialize};

use crate::builder::verify::TendermintVerify;
use crate::config::TendermintConfig;
use crate::input::InputDataFetcher;
use crate::variables::*;

pub trait TendermintSkipCircuit<L: PlonkParameters<D>, const D: usize> {
    fn skip<const MAX_VALIDATOR_SET_SIZE: usize, const CHAIN_ID_SIZE_BYTES: usize>(
        &mut self,
        chain_id_bytes: &[u8],
        skip_max: usize,
        trusted_block: U64Variable,
        trusted_header_hash: Bytes32Variable,
        target_block: U64Variable,
    ) -> Bytes32Variable;
}

impl<L: PlonkParameters<D>, const D: usize> TendermintSkipCircuit<L, D> for CircuitBuilder<L, D> {
    fn skip<const MAX_VALIDATOR_SET_SIZE: usize, const CHAIN_ID_SIZE_BYTES: usize>(
        &mut self,
        chain_id_bytes: &[u8],
        skip_max: usize,
        trusted_block: U64Variable,
        trusted_header_hash: Bytes32Variable,
        target_block: U64Variable,
    ) -> Bytes32Variable {
        let mut input_stream = VariableStream::new();
        input_stream.write(&trusted_block);
        input_stream.write(&trusted_header_hash);
        input_stream.write(&target_block);
        let output_stream = self.async_hint(
            input_stream,
            SkipOffchainInputs::<MAX_VALIDATOR_SET_SIZE> {},
        );
        let skip_variable = output_stream.read::<VerifySkipVariable<MAX_VALIDATOR_SET_SIZE>>(self);
        // Assert that skip_variable is connected to the provided inputs.
        self.assert_is_equal(skip_variable.trusted_block, trusted_block);
        self.assert_is_equal(skip_variable.trusted_header, trusted_header_hash);
        self.assert_is_equal(skip_variable.target_block, target_block);
        self.verify_skip::<MAX_VALIDATOR_SET_SIZE, CHAIN_ID_SIZE_BYTES>(
            chain_id_bytes,
            skip_max,
            &skip_variable,
        );
        skip_variable.target_header
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkipOffchainInputs<const MAX_VALIDATOR_SET_SIZE: usize> {}

#[async_trait]
impl<const MAX_VALIDATOR_SET_SIZE: usize, L: PlonkParameters<D>, const D: usize> AsyncHint<L, D>
    for SkipOffchainInputs<MAX_VALIDATOR_SET_SIZE>
{
    async fn hint(
        &self,
        input_stream: &mut ValueStream<L, D>,
        output_stream: &mut ValueStream<L, D>,
    ) {
        let trusted_block = input_stream.read_value::<U64Variable>();
        let trusted_header_hash = input_stream.read_value::<Bytes32Variable>();
        let target_block = input_stream.read_value::<U64Variable>();
        let mut data_fetcher = InputDataFetcher::default();
        let result = data_fetcher
            .get_skip_inputs::<MAX_VALIDATOR_SET_SIZE, L::Field>(
                trusted_block,
                trusted_header_hash,
                target_block,
            )
            .await;

        let verify_skip_struct = VerifySkipStruct::<MAX_VALIDATOR_SET_SIZE, L::Field> {
            target_header: result.target_header.into(),
            target_block,
            target_block_validators: result.target_block_validators,
            target_block_nb_validators: L::Field::from_canonical_usize(result.nb_target_validators),
            target_block_round: result.round as u64,
            target_header_chain_id_proof: result.target_block_chain_id_proof,
            target_header_height_proof: result.target_block_height_proof,
            target_header_validator_hash_proof: result.target_block_validators_hash_proof,
            trusted_header: result.trusted_header.into(),
            trusted_block,
            trusted_block_nb_validators: L::Field::from_canonical_usize(
                result.nb_trusted_validators,
            ),
            trusted_header_validator_hash_proof: result.trusted_block_validators_hash_proof,
            trusted_header_validator_hash_fields: result.trusted_block_validators_hash_fields,
        };

        output_stream.write_value::<VerifySkipVariable<MAX_VALIDATOR_SET_SIZE>>(verify_skip_struct);
    }
}

#[derive(Debug, Clone)]
pub struct SkipCircuit<
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
    > Circuit for SkipCircuit<MAX_VALIDATOR_SET_SIZE, CHAIN_ID_SIZE_BYTES, C>
{
    fn define<L: PlonkParameters<D>, const D: usize>(builder: &mut CircuitBuilder<L, D>) {
        let trusted_block = builder.evm_read::<U64Variable>();
        let trusted_header_hash = builder.evm_read::<Bytes32Variable>();
        let target_block = builder.evm_read::<U64Variable>();

        let target_header_hash = builder.skip::<MAX_VALIDATOR_SET_SIZE, CHAIN_ID_SIZE_BYTES>(
            C::CHAIN_ID_BYTES,
            C::SKIP_MAX,
            trusted_block,
            trusted_header_hash,
            target_block,
        );

        builder.evm_write(target_header_hash);
    }

    fn register_generators<L: PlonkParameters<D>, const D: usize>(
        generator_registry: &mut plonky2x::prelude::HintRegistry<L, D>,
    ) where
        <<L as PlonkParameters<D>>::Config as plonky2x::prelude::plonky2::plonk::config::GenericConfig<D>>::Hasher:
            plonky2x::prelude::plonky2::plonk::config::AlgebraicHasher<L::Field>,
    {
        generator_registry.register_async_hint::<SkipOffchainInputs<MAX_VALIDATOR_SET_SIZE>>();
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
    use crate::config::{Mocha4Config, MOCHA_4_CHAIN_ID_SIZE_BYTES};

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_skip_serialization() {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        const MAX_VALIDATOR_SET_SIZE: usize = 2;

        let mut builder = DefaultBuilder::new();

        log::debug!("Defining circuit");

        SkipCircuit::<MAX_VALIDATOR_SET_SIZE, MOCHA_4_CHAIN_ID_SIZE_BYTES, Mocha4Config>::define(
            &mut builder,
        );

        let circuit = builder.build();
        log::debug!("Done building circuit");

        let mut hint_registry = HintRegistry::new();
        let mut gate_registry = GateRegistry::new();
        SkipCircuit::<MAX_VALIDATOR_SET_SIZE, MOCHA_4_CHAIN_ID_SIZE_BYTES, Mocha4Config>::register_generators(
            &mut hint_registry,
        );
        SkipCircuit::<MAX_VALIDATOR_SET_SIZE, MOCHA_4_CHAIN_ID_SIZE_BYTES, Mocha4Config>::register_gates(
            &mut gate_registry,
        );

        circuit.test_serializers(&gate_registry, &hint_registry);
    }

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_skip_circuit_with_input_bytes() {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        const MAX_VALIDATOR_SET_SIZE: usize = 4;

        // This is from block 3000 with requested block 3100
        let input_bytes = hex::decode(
            "0000000000000bb8a8512f18c34b70e1533cfd5aa04f251fcb0d7be56ec570051fbad9bdb9435e6a0000000000000c1c",
        )
        .unwrap();

        let mut builder = DefaultBuilder::new();

        log::debug!("Defining circuit");
        SkipCircuit::<MAX_VALIDATOR_SET_SIZE, MOCHA_4_CHAIN_ID_SIZE_BYTES, Mocha4Config>::define(
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

    fn test_skip_template<const MAX_VALIDATOR_SET_SIZE: usize>(
        trusted_header: [u8; 32],
        trusted_block: u64,
        target_block: u64,
    ) {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        let mut builder = DefaultBuilder::new();

        log::debug!("Defining circuit");
        SkipCircuit::<MAX_VALIDATOR_SET_SIZE, MOCHA_4_CHAIN_ID_SIZE_BYTES, Mocha4Config>::define(
            &mut builder,
        );

        log::debug!("Building circuit");
        let circuit = builder.build();
        log::debug!("Done building circuit");

        let mut input = circuit.input();
        input.evm_write::<U64Variable>(trusted_block);
        input.evm_write::<Bytes32Variable>(H256::from_slice(trusted_header.as_slice()));
        input.evm_write::<U64Variable>(target_block);

        log::debug!("Generating proof");
        let (proof, mut output) = circuit.prove(&input);
        log::debug!("Done generating proof");

        circuit.verify(&proof, &input, &output);
        let target_header = output.evm_read::<Bytes32Variable>();
        println!("target_header {:?}", target_header);
    }

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_skip_small() {
        const MAX_VALIDATOR_SET_SIZE: usize = 4;
        let trusted_header: [u8; 32] =
            hex::decode("A0123D5E4B8B8888A61F931EE2252D83568B97C223E0ECA9795B29B8BD8CBA2D")
                .unwrap()
                .try_into()
                .unwrap();
        let trusted_height = 10000u64;
        let target_height = 10500u64;
        test_skip_template::<MAX_VALIDATOR_SET_SIZE>(trusted_header, trusted_height, target_height)
    }

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_skip_medium() {
        const MAX_VALIDATOR_SET_SIZE: usize = 32;
        let trusted_block = 10000u64;
        let trusted_header_hash =
            hex::decode("A0123D5E4B8B8888A61F931EE2252D83568B97C223E0ECA9795B29B8BD8CBA2D")
                .unwrap()
                .try_into()
                .unwrap();
        let target_block = 10500u64;
        test_skip_template::<MAX_VALIDATOR_SET_SIZE>(
            trusted_header_hash,
            trusted_block,
            target_block,
        )
    }

    #[tokio::test]
    #[cfg_attr(feature = "ci", ignore)]
    async fn test_skip_large() {
        const MAX_VALIDATOR_SET_SIZE: usize = 100;
        let trusted_header: [u8; 32] =
            hex::decode("959d6d73b5536c66303cee2b1314d346ac3e22b11df7fef3f5f4afe166867527")
                .unwrap()
                .try_into()
                .unwrap();
        let trusted_height = 1260790u64;
        let target_height = 1261790u64;
        test_skip_template::<MAX_VALIDATOR_SET_SIZE>(trusted_header, trusted_height, target_height)
    }
}
