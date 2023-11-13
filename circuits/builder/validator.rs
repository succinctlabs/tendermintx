use plonky2x::frontend::curta::ec::point::CompressedEdwardsYVariable;
use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::frontend::vars::U32Variable;
use plonky2x::prelude::{
    BoolVariable, ByteVariable, BytesVariable, CircuitBuilder, CircuitVariable, PlonkParameters,
    Variable,
};

use super::shared::TendermintHeader;
use crate::consts::VALIDATOR_BYTE_LENGTH_MAX;
use crate::variables::{MarshalledValidatorVariable, TendermintHashVariable};

pub trait TendermintValidator<L: PlonkParameters<D>, const D: usize> {
    /// Serializes the validator public key and voting power to bytes.
    /// The protobuf encoding of a Tendermint validator is a deterministic function of the validator's
    /// public key (32 bytes) and voting power (int64). The encoding is as follows in bytes:
    /// 10 34 10 32 <pubkey> 16 <varint>
    /// The `pubkey` is encoded as the raw list of bytes used in the public key. The `varint` is
    /// encoded using protobuf's default integer encoding, which consist of 7 bit payloads. You can
    /// read more about them here: https://protobuf.dev/programming-guides/encoding/#varints.  
    fn marshal_tendermint_validator(
        &mut self,
        pubkey: &CompressedEdwardsYVariable,
        voting_power: &U64Variable,
    ) -> MarshalledValidatorVariable;

    /// Hash validator bytes as leaf according to the Tendermint spec. (0x00 || validatorBytes)
    fn hash_validator_leaf(
        &mut self,
        validator: &MarshalledValidatorVariable,
        validator_byte_length: Variable,
    ) -> TendermintHashVariable;

    /// Compute the expected validator hash from the validator set.
    fn hash_validator_set<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        validators: &[MarshalledValidatorVariable],
        validator_byte_lengths: &[Variable],
        validator_enabled: Vec<BoolVariable>,
    ) -> TendermintHashVariable;
}

impl<L: PlonkParameters<D>, const D: usize> TendermintValidator<L, D> for CircuitBuilder<L, D> {
    fn marshal_tendermint_validator(
        &mut self,
        pubkey: &CompressedEdwardsYVariable,
        voting_power: &U64Variable,
    ) -> MarshalledValidatorVariable {
        // The encoding is as follows in bytes: 10 34 10 32 <pubkey> 16 <varint>
        let mut res = self
            .constant::<BytesVariable<4>>([10u8, 34u8, 10u8, 32u8])
            .0
            .to_vec();

        res.extend_from_slice(&pubkey.0.as_bytes());

        res.push(self.constant::<ByteVariable>(16u8));

        // The remaining bytes of the serialized validator are the voting power as a "varint".
        let voting_power_serialized = self.marshal_int64_varint(voting_power);
        res.extend_from_slice(&voting_power_serialized);

        assert_eq!(res.len(), VALIDATOR_BYTE_LENGTH_MAX);

        BytesVariable::<VALIDATOR_BYTE_LENGTH_MAX>(res.try_into().unwrap())
    }

    fn hash_validator_leaf(
        &mut self,
        validator: &MarshalledValidatorVariable,
        validator_byte_length: Variable,
    ) -> TendermintHashVariable {
        let one = self.one::<Variable>();

        // The encoding is as follows in bytes: 0x00 || validatorBytes
        let mut validator_bytes = vec![self.zero::<ByteVariable>()];
        validator_bytes.extend(validator.0.to_vec());

        let enc_validator_byte_length = self.add(one, validator_byte_length);

        let input_byte_length = U32Variable::from_variables(self, &[enc_validator_byte_length]);

        // Resize the validator bytes to 64 bytes (1 chunk).
        validator_bytes.resize(64, self.zero::<ByteVariable>());

        // Hash the validator bytes.
        self.curta_sha256_variable(&validator_bytes, input_byte_length)
    }

    fn hash_validator_set<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        validators: &[MarshalledValidatorVariable],
        validator_byte_lengths: &[Variable],
        validator_enabled: Vec<BoolVariable>,
    ) -> TendermintHashVariable {
        assert_eq!(validators.len(), VALIDATOR_SET_SIZE_MAX);
        assert_eq!(validator_byte_lengths.len(), VALIDATOR_SET_SIZE_MAX);
        assert_eq!(validator_enabled.len(), VALIDATOR_SET_SIZE_MAX);

        // Hash each of the validators to get corresponding leaf hash.
        let mut validator_leaf_hashes = Vec::new();
        for i in 0..VALIDATOR_SET_SIZE_MAX {
            validator_leaf_hashes
                .push(self.hash_validator_leaf(&validators[i], validator_byte_lengths[i]))
        }

        // Return the root hash.
        self.get_root_from_hashed_leaves::<VALIDATOR_SET_SIZE_MAX>(
            validator_leaf_hashes,
            validator_enabled,
        )
    }
}

// To run tests with logs (i.e. to see proof generation time), set the environment variable `RUST_LOG=debug` before the test command.
// Alternatively, add env::set_var("RUST_LOG", "debug") to the top of the test.
#[cfg(test)]
pub(crate) mod tests {
    use ethers::types::H256;
    use ethers::utils::hex;
    use itertools::Itertools;
    use plonky2x::frontend::curta::ec::point::CompressedEdwardsY;
    use plonky2x::frontend::merkle::tree::{InclusionProof, MerkleInclusionProofVariable};
    use plonky2x::prelude::{
        ArrayVariable, Bytes32Variable, DefaultBuilder, Field, GoldilocksField,
    };
    use tendermint_proto::types::BlockId as RawBlockId;
    use tendermint_proto::Protobuf;
    use tokio::runtime::Runtime;

    use super::*;
    use crate::consts::{HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES};
    use crate::input::tendermint_utils::{generate_proofs_from_header, proofs_from_byte_slices};
    use crate::input::utils::{convert_to_h256, get_path_indices};
    use crate::input::InputDataFetcher;

    #[test]
    fn test_marshal_tendermint_validator() {
        env_logger::try_init().unwrap_or_default();

        // This is a test cases generated from a validator in block 11000 of the mocha-3 testnet.
        let voting_power_i64 = 100010_i64;
        let pubkey = "de25aec935b10f657b43fa97e5a8d4e523bdb0f9972605f0b064eff7b17048ba";
        let expected_marshal = hex::decode(
            "0a220a20de25aec935b10f657b43fa97e5a8d4e523bdb0f9972605f0b064eff7b17048ba10aa8d06",
        )
        .unwrap();

        // Define the circuit
        let mut builder = DefaultBuilder::new();
        let voting_power_variable = builder.read::<U64Variable>();
        let pub_key = builder.read::<CompressedEdwardsYVariable>();
        let result = builder.marshal_tendermint_validator(&pub_key, &voting_power_variable);
        builder.write(result);
        let circuit = builder.build();

        let mut input = circuit.input();
        input.write::<U64Variable>(voting_power_i64 as u64);
        let pub_key_uncompressed =
            CompressedEdwardsY::from_slice(&hex::decode(pubkey).unwrap()).unwrap();
        input.write::<CompressedEdwardsYVariable>(pub_key_uncompressed);
        let (_, mut output) = circuit.prove(&input);
        let output_bytes = output.read::<BytesVariable<VALIDATOR_BYTE_LENGTH_MAX>>();

        for i in 0..VALIDATOR_BYTE_LENGTH_MAX {
            let expected_value = *expected_marshal.get(i).unwrap_or(&0);
            assert_eq!(output_bytes[i], expected_value);
        }
    }

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_generate_validators_hash() {
        const VALIDATOR_SET_SIZE_MAX: usize = 4;

        env_logger::try_init().unwrap_or_default();

        // Define the circuit
        let mut builder = DefaultBuilder::new();
        let messages =
            builder.read::<ArrayVariable<MarshalledValidatorVariable, VALIDATOR_SET_SIZE_MAX>>();
        let val_byte_lengths = builder.read::<ArrayVariable<Variable, VALIDATOR_SET_SIZE_MAX>>();
        let val_enabled = builder.read::<ArrayVariable<BoolVariable, VALIDATOR_SET_SIZE_MAX>>();

        let root = builder.hash_validator_set::<VALIDATOR_SET_SIZE_MAX>(
            &messages.as_vec(),
            &val_byte_lengths.as_vec(),
            val_enabled.as_vec(),
        );
        builder.write(root);
        let circuit = builder.build();

        let validators_arr: Vec<Vec<&str>> = vec![vec![
            "0a220a20de25aec935b10f657b43fa97e5a8d4e523bdb0f9972605f0b064eff7b17048ba10aa8d06",
            "0a220a208de6ad1a569a223e7bb0dade194abb9487221210e1fa8154bf654a10fe6158a610aa8d06",
            "0a220a20e9b7638ca1c42da37d728970632fda77ec61dcc520395ab5d3a645b9c2b8e8b1100a",
            "0a220a20bd60452e7f056b22248105e7fd298961371da0d9332ef65fa81691bf51b2e5051001",
        ], vec!["364db94241a02b701d0dc85ac016fab2366fba326178e6f11d8294931969072b7441fd6b0ff5129d6867", "6fa0cef8f328eb8e2aef2084599662b1ee0595d842058966166029e96bd263e5367185f19af67b099645ec08aa", "0a220a20bd60452e7f056b22248105e7fd298961371da0d9332ef65fa81691bf51b2e5051001", "0a220a20bd60452e7f056b22248105e7fd298961371da0d9332ef65fa81691bf51b2e5051001"]];

        let validators: Vec<Vec<Vec<u8>>> = validators_arr
            .iter()
            .map(|x| {
                x.iter()
                    .map(|y| hex::decode(y).unwrap())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let validators_byte_lengths = validators
            .iter()
            .map(|x| {
                x.iter()
                    .map(|y| GoldilocksField::from_canonical_usize(y.len()))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let validators_enabled = vec![vec![true, true, true, true], vec![true, true, true, true]];

        // Compute the expected hash_validator_set roots.
        let expected_roots: Vec<H256> = validators
            .iter()
            .map(|batch| H256::from(proofs_from_byte_slices(batch.to_vec()).0))
            .collect::<Vec<_>>();

        let mut input = circuit.input();
        input.write::<ArrayVariable<MarshalledValidatorVariable, VALIDATOR_SET_SIZE_MAX>>(
            validators[0]
                .iter()
                .map(|x| {
                    // Resize the input bytes to VALIDATOR_BYTE_LENGTH_MAX.
                    let mut validator_bytes = x.clone();
                    validator_bytes.resize(VALIDATOR_BYTE_LENGTH_MAX, 0u8);
                    let arr: [u8; VALIDATOR_BYTE_LENGTH_MAX] = validator_bytes.try_into().unwrap();
                    arr
                })
                .collect_vec(),
        );
        input.write::<ArrayVariable<Variable, VALIDATOR_SET_SIZE_MAX>>(
            validators_byte_lengths[0].clone(),
        );
        input.write::<ArrayVariable<BoolVariable, VALIDATOR_SET_SIZE_MAX>>(
            validators_enabled[0].clone(),
        );
        let (_, mut output) = circuit.prove(&input);
        let computed_root = output.read::<Bytes32Variable>();
        assert_eq!(expected_roots[0], computed_root);
    }

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_get_root_from_merkle_proof() {
        env_logger::try_init().unwrap_or_default();

        // Define the circuit
        let mut builder = DefaultBuilder::new();
        let proof = builder
            .read::<MerkleInclusionProofVariable<HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES>>(
            );
        let path_indices = builder.read::<ArrayVariable<BoolVariable, HEADER_PROOF_DEPTH>>();
        let root = builder.get_root_from_merkle_proof(&proof, &path_indices);
        builder.write(root);
        let circuit = builder.build();

        // Generate test cases from Celestia mocha-4 header 10000:
        let input_data_fetcher = InputDataFetcher::default();

        let rt = Runtime::new().expect("failed to create tokio runtime");
        let signed_header = rt.block_on(async {
            input_data_fetcher
                .get_signed_header_from_number(10000u64)
                .await
        });

        let (root, proofs) = generate_proofs_from_header(&signed_header.header);

        // Can test with leaf_index 2, 4, 6, 7 or 8 (height, last_block_id_hash, data_hash, validators_hash, next_validators_hash)
        // TODO: Add tests for all leaf indices that are used.
        let leaf_index = 4;

        // Note: Must convert to protobuf encoding (get_proofs_from_header is a good reference)
        let leaf = Protobuf::<RawBlockId>::encode_vec(
            signed_header.header.last_block_id.unwrap_or_default(),
        );

        let path_indices = get_path_indices(leaf_index as u64, proofs[0].total);

        let proof = InclusionProof {
            proof: convert_to_h256(proofs[leaf_index].clone().aunts),
            leaf: leaf.try_into().unwrap(),
        };

        let mut input = circuit.input();
        input.write::<MerkleInclusionProofVariable<HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES>>(
            proof,
        );
        input.write::<ArrayVariable<BoolVariable, HEADER_PROOF_DEPTH>>(path_indices);
        let (_, mut output) = circuit.prove(&input);
        let computed_root = output.read::<Bytes32Variable>();

        assert_eq!(H256::from(root), computed_root);
    }
}
