use plonky2x::frontend::curta::ec::point::CompressedEdwardsYVariable;
use plonky2x::frontend::ecc::curve25519::ed25519::eddsa::EDDSASignatureVariable;
use plonky2x::frontend::merkle::tendermint::TendermintMerkleTree;
use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::frontend::vars::{ByteVariable, U32Variable};
use plonky2x::prelude::{
    ArrayVariable, BoolVariable, Bytes32Variable, BytesVariable, CircuitBuilder, CircuitVariable,
    Field, PlonkParameters, Variable,
};

use super::shared::TendermintHeader;
use super::validator::TendermintValidator;
use super::voting::TendermintVoting;
use crate::consts::{
    CHAIN_ID_INDEX, HASH_SIZE, HEADER_PROOF_DEPTH, LAST_BLOCK_ID_INDEX, NEXT_VALIDATORS_HASH_INDEX,
    VALIDATORS_HASH_INDEX, VALIDATOR_MESSAGE_BYTES_LENGTH_MAX,
};
use crate::variables::*;

pub trait TendermintVerify<L: PlonkParameters<D>, const D: usize> {
    /// Verify the header hash of the previous block matches the new block's parent hash.
    fn verify_prev_header_in_header(
        &mut self,
        header: &TendermintHashVariable,
        prev_header: TendermintHashVariable,
        last_block_id_proof: &BlockIDInclusionProofVariable,
    );

    /// Verify the next validators hash in the previous block matches the new block's validators hash.
    fn verify_prev_header_next_validators_hash(
        &mut self,
        new_validators_hash: TendermintHashVariable,
        prev_header: &TendermintHashVariable,
        prev_header_next_validators_hash_proof: &HashInclusionProofVariable,
    );

    /// Verify the chain ID against the header.
    fn verify_chain_id<const CHAIN_ID_SIZE_BYTES: usize>(
        &mut self,
        expected_chain_id_bytes: &[u8],
        chain_id_proof: &ChainIdProofVariable,
        header: &TendermintHashVariable,
    );

    /// Verify a Tendermint consensus block. Specifically, verify that 2/3 of the validator set
    /// specified in the header signed on a Precommit message that includes the header hash, and
    /// that the chain ID in the header matches the expected chain ID.
    fn verify_header<const VALIDATOR_SET_SIZE_MAX: usize, const CHAIN_ID_SIZE_BYTES: usize>(
        &mut self,
        expected_chain_id_bytes: &[u8],
        validators: &ArrayVariable<ValidatorVariable, VALIDATOR_SET_SIZE_MAX>,
        nb_enabled_validators: Variable,
        header: &TendermintHashVariable,
        height: &U64Variable,
        chain_id_proof: &ChainIdProofVariable,
        height_proof: &HeightProofVariable,
        validator_hash_proof: &HashInclusionProofVariable,
        round: &U64Variable,
    );

    /// Compute the validators hash from the necessary fields. If a validator is not enabled, then
    /// do not include it in the hash.
    fn compute_validators_hash<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        validators: &ArrayVariable<ValidatorHashFieldVariable, VALIDATOR_SET_SIZE_MAX>,
        nb_enabled_validators: Variable,
    ) -> TendermintHashVariable;

    /// Verify the set of validators who've signed on the commit from the target block comprise more
    /// than 1/3 of the voting power on the trusted block.
    fn verify_trusted_validators<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        validators: &ArrayVariable<ValidatorVariable, VALIDATOR_SET_SIZE_MAX>,
        trusted_header: TendermintHashVariable,
        trusted_validator_hash_proof: &HashInclusionProofVariable,
        trusted_validator_hash_fields: &ArrayVariable<
            ValidatorHashFieldVariable,
            VALIDATOR_SET_SIZE_MAX,
        >,
        trusted_nb_enabled_validators: Variable,
    );

    /// Assert the voting power of the included validators is greater than the threshold
    /// (threshold_numerator / threshold_denominator).
    fn verify_voting_threshold<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        validator_voting_power: &[U64Variable],
        nb_enabled_validators: Variable,
        threshold_numerator: &U64Variable,
        threshold_denominator: &U64Variable,
        include_in_check: &[BoolVariable],
    );

    /// Sequentially verify a Tendermint consensus block. Verify that a) the next validators hash in
    /// the previous block matches the current block's validators hash, b) the header hash
    /// of the previous block matches the current block's parent hash and c) 2/3 of the validators
    /// in the current block's validators hash signed the current block.
    ///
    /// Note: Only used if a satisfying pair of blocks for skipping intermediate verification is not
    /// found, which is extremely rare.
    fn verify_step<const VALIDATOR_SET_SIZE_MAX: usize, const CHAIN_ID_SIZE_BYTES: usize>(
        &mut self,
        expected_chain_id_bytes: &[u8],
        prev_block_number: U64Variable,
        prev_header_hash: Bytes32Variable,
        step: &VerifyStepVariable<VALIDATOR_SET_SIZE_MAX>,
    );

    /// Verify trusted_block + SKIP_MAX > target_block > trusted_block + 1. The target block must be
    /// greater than & non-adjacent to the trusted_block, and must be less than SKIP_MAX blocks
    /// away from the trusted_block.
    fn verify_skip_distance(
        &mut self,
        skip_max: usize,
        trusted_block: &U64Variable,
        target_block: &U64Variable,
    );

    /// Verify a Tendermint block that is non-sequential with the trusted block. More than 1/3 of the
    /// stake on the new block must be from validators on the trusted block to skip intermediate
    /// verification. Additionally, the new block must have 2/3 of the validators signed on it.
    ///
    /// Note: Skip verification is valid while the time elapsed between the trusted block and the
    /// new block is less than the unbonding period. This is checked in the smart contract.
    fn verify_skip<const VALIDATOR_SET_SIZE_MAX: usize, const CHAIN_ID_SIZE_BYTES: usize>(
        &mut self,
        expected_chain_id_bytes: &[u8],
        skip_max: usize,
        trusted_block: U64Variable,
        trusted_header_hash: Bytes32Variable,
        target_block: U64Variable,
        skip: &VerifySkipVariable<VALIDATOR_SET_SIZE_MAX>,
    );
}

impl<L: PlonkParameters<D>, const D: usize> TendermintVerify<L, D> for CircuitBuilder<L, D> {
    fn verify_prev_header_in_header(
        &mut self,
        header: &TendermintHashVariable,
        prev_header: TendermintHashVariable,
        last_block_id_proof: &BlockIDInclusionProofVariable,
    ) {
        let last_block_id_path = self.get_path_to_leaf(LAST_BLOCK_ID_INDEX);

        // Assert the last block id came from this header.
        let header_from_last_block_id_proof =
            self.get_root_from_merkle_proof(last_block_id_proof, &last_block_id_path);
        self.assert_is_equal(header_from_last_block_id_proof, *header);

        // Assert the previous header from the last block id proof matches the previous header.
        let extracted_prev_header_hash: Bytes32Variable =
            last_block_id_proof.leaf[2..2 + HASH_SIZE].into();
        self.assert_is_equal(prev_header, extracted_prev_header_hash);
    }

    fn verify_prev_header_next_validators_hash(
        &mut self,
        new_validators_hash: TendermintHashVariable,
        prev_header: &TendermintHashVariable,
        prev_header_next_validators_hash_proof: &HashInclusionProofVariable,
    ) {
        let next_val_hash_path = self.get_path_to_leaf(NEXT_VALIDATORS_HASH_INDEX);

        // Assert the root of the next validators hash proof matches the prev header hash.
        let computed_prev_header_root = self.get_root_from_merkle_proof(
            prev_header_next_validators_hash_proof,
            &next_val_hash_path,
        );
        self.assert_is_equal(computed_prev_header_root, *prev_header);

        // Assert the new validators hash matches the next validators' hash of the previous header.
        let extracted_prev_header_next_validators_hash =
            prev_header_next_validators_hash_proof.leaf[2..2 + HASH_SIZE].into();
        self.assert_is_equal(
            new_validators_hash,
            extracted_prev_header_next_validators_hash,
        );
    }

    fn verify_chain_id<const CHAIN_ID_SIZE_BYTES: usize>(
        &mut self,
        expected_chain_id_bytes: &[u8],
        chain_id_proof: &ChainIdProofVariable,
        header: &TendermintHashVariable,
    ) {
        let chain_id_path = self.get_path_to_leaf(CHAIN_ID_INDEX);

        // Leaf encode the protobuf-encoded chain ID bytes for hashing.
        let mut extended_chain_id_bytes = self.constant::<BytesVariable<1>>([0x00]).0.to_vec();
        extended_chain_id_bytes.extend_from_slice(&chain_id_proof.chain_id.data);

        // Extend the leaf-encoded chain ID bytes to 64 bytes for variable SHA256 hashing.
        extended_chain_id_bytes.resize(64, self.zero::<ByteVariable>());

        // Add 1 to the encoded chain id byte length to account for the 0x00 leaf prefix byte.
        let one_u32 = self.constant::<U32Variable>(1);
        let encoded_chain_id_byte_length =
            self.add(chain_id_proof.enc_chain_id_byte_length, one_u32);

        // Hash the leaf-encoded chain ID bytes.
        let leaf_hash =
            self.curta_sha256_variable(&extended_chain_id_bytes, encoded_chain_id_byte_length);

        // Verify the computed header from the chain id proof against the header.
        let computed_header = self.get_root_from_merkle_proof_hashed_leaf::<HEADER_PROOF_DEPTH>(
            &chain_id_proof.proof,
            &chain_id_path,
            leaf_hash,
        );
        self.assert_is_equal(computed_header, *header);

        // Extract the chain ID bytes from the chain ID proof against the header and assert it
        // matches the expected chain ID bytes.
        let extracted_chain_id: ArrayVariable<ByteVariable, CHAIN_ID_SIZE_BYTES> = chain_id_proof
            .chain_id[2..2 + CHAIN_ID_SIZE_BYTES]
            .to_vec()
            .into();
        let expected_chain_id = self.constant::<ArrayVariable<ByteVariable, CHAIN_ID_SIZE_BYTES>>(
            expected_chain_id_bytes.to_vec(),
        );
        self.assert_is_equal(extracted_chain_id, expected_chain_id);
    }

    fn verify_header<const VALIDATOR_SET_SIZE_MAX: usize, const CHAIN_ID_SIZE_BYTES: usize>(
        &mut self,
        expected_chain_id_bytes: &[u8],
        validators: &ArrayVariable<ValidatorVariable, VALIDATOR_SET_SIZE_MAX>,
        nb_enabled_validators: Variable,
        header: &TendermintHashVariable,
        height: &U64Variable,
        chain_id_proof: &ChainIdProofVariable,
        height_proof: &HeightProofVariable,
        validator_hash_proof: &HashInclusionProofVariable,
        round: &U64Variable,
    ) {
        // Extract the necessary data for verifying the validators' signatures.
        let (mut signed, mut messages, mut message_byte_lengths, mut signatures, mut pubkeys) =
            (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for v in &validators.data {
            signed.push(v.signed);
            messages.push(v.message);
            message_byte_lengths.push(U32Variable::from_variables(self, &[v.message_byte_length]));
            signatures.push(v.signature.clone());
            pubkeys.push(v.pubkey.clone());
        }

        // Verify the signatures of the validators that signed the header.
        self.curta_eddsa_verify_sigs_conditional(
            ArrayVariable::<BoolVariable, VALIDATOR_SET_SIZE_MAX>::new(signed.clone()),
            Some(ArrayVariable::<U32Variable, VALIDATOR_SET_SIZE_MAX>::new(
                message_byte_lengths,
            )),
            ArrayVariable::<
                BytesVariable<VALIDATOR_MESSAGE_BYTES_LENGTH_MAX>,
                VALIDATOR_SET_SIZE_MAX,
            >::new(messages.clone()),
            ArrayVariable::<EDDSASignatureVariable, VALIDATOR_SET_SIZE_MAX>::new(signatures),
            ArrayVariable::<CompressedEdwardsYVariable, VALIDATOR_SET_SIZE_MAX>::new(pubkeys),
        );

        // Compute the validators hash of the validators from the necessary fields.
        let validator_hash_fields: Vec<ValidatorHashFieldVariable> = validators
            .as_vec()
            .iter()
            .map(|v| ValidatorHashFieldVariable {
                pubkey: v.pubkey.clone(),
                voting_power: v.voting_power,
                validator_byte_length: v.validator_byte_length,
            })
            .collect();
        let computed_validators_hash = self.compute_validators_hash(
            &ArrayVariable::<ValidatorHashFieldVariable, VALIDATOR_SET_SIZE_MAX>::new(
                validator_hash_fields,
            ),
            nb_enabled_validators,
        );

        // Assert the computed validator hash matches the expected validator hash.
        let extracted_hash: Bytes32Variable = validator_hash_proof.leaf[2..2 + HASH_SIZE].into();
        self.assert_is_equal(extracted_hash, computed_validators_hash);

        // Assert the validators hash came from this header.
        let val_hash_path = self.get_path_to_leaf(VALIDATORS_HASH_INDEX);
        let header_from_validator_root_proof =
            self.get_root_from_merkle_proof(validator_hash_proof, &val_hash_path);
        self.assert_is_equal(*header, header_from_validator_root_proof);

        // Assert signed validators comprise more than 2/3 of the total voting power.
        let threshold_numerator = self.constant::<U64Variable>(2);
        let threshold_denominator = self.constant::<U64Variable>(3);

        let validator_voting_power = validators
            .as_vec()
            .iter()
            .map(|v| v.voting_power)
            .collect::<Vec<_>>();
        self.verify_voting_threshold::<VALIDATOR_SET_SIZE_MAX>(
            &validator_voting_power,
            nb_enabled_validators,
            &threshold_numerator,
            &threshold_denominator,
            &signed,
        );

        // Verify each validator's signature is valid.
        let mut is_enabled = self._true();
        for i in 0..VALIDATOR_SET_SIZE_MAX {
            let idx = self.constant::<Variable>(L::Field::from_canonical_usize(i));

            // If at_end, then the rest of the leaves (including this one) are disabled.
            let at_end = self.is_equal(idx, nb_enabled_validators);
            let not_at_end = self.not(at_end);
            is_enabled = self.and(not_at_end, is_enabled);

            self.verify_validator_signature_data(
                header,
                height,
                &messages[i],
                &is_enabled,
                &signed[i],
                round,
            );
        }

        // Verify the chain ID against the header.
        self.verify_chain_id::<CHAIN_ID_SIZE_BYTES>(
            expected_chain_id_bytes,
            chain_id_proof,
            header,
        );

        // Verify the block's height is correct.
        self.verify_block_height(*header, height_proof.clone(), *height);
    }

    fn compute_validators_hash<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        validators: &ArrayVariable<ValidatorHashFieldVariable, VALIDATOR_SET_SIZE_MAX>,
        nb_enabled_validators: Variable,
    ) -> TendermintHashVariable {
        // Extract the necessary fields.
        let byte_lengths: Vec<Variable> = validators
            .as_vec()
            .iter()
            .map(|v| v.validator_byte_length)
            .collect();
        let marshalled_validators: Vec<MarshalledValidatorVariable> = validators
            .as_vec()
            .iter()
            .map(|v| self.marshal_tendermint_validator(&v.pubkey, &v.voting_power))
            .collect();

        // Compute the validators hash of the validator set.
        self.hash_validator_set::<VALIDATOR_SET_SIZE_MAX>(
            &marshalled_validators,
            &byte_lengths,
            nb_enabled_validators,
        )
    }

    fn verify_trusted_validators<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        validators: &ArrayVariable<ValidatorVariable, VALIDATOR_SET_SIZE_MAX>,
        trusted_header: TendermintHashVariable,
        trusted_validator_hash_proof: &HashInclusionProofVariable,
        trusted_validator_hash_fields: &ArrayVariable<
            ValidatorHashFieldVariable,
            VALIDATOR_SET_SIZE_MAX,
        >,
        trusted_nb_enabled_validators: Variable,
    ) {
        let true_var = self._true();
        // Retrieve the header from the validator hash Merkle proof.
        let val_hash_path = self.get_path_to_leaf(VALIDATORS_HASH_INDEX);
        let header_from_validator_root_proof =
            self.get_root_from_merkle_proof(trusted_validator_hash_proof, &val_hash_path);

        // Ensure the trusted validator hash proof aligns with the trusted header.
        self.assert_is_equal(header_from_validator_root_proof, trusted_header);

        // Calculate the validators hash of the trusted block using the provided fields.
        let computed_val_hash = self
            .compute_validators_hash(trusted_validator_hash_fields, trusted_nb_enabled_validators);

        // Extract the expected trusted validators hash from the valid validators hash proof.
        let expected_val_hash = trusted_validator_hash_proof.leaf[2..2 + HASH_SIZE].into();

        // Confirm the computed validators hash matches the expected hash.
        self.assert_is_equal(computed_val_hash, expected_val_hash);

        // Indicator for each trusted validator to determine if it has signed the commit on the target block.
        let mut trusted_validator_signed_on_target_header =
            vec![self._false(); VALIDATOR_SET_SIZE_MAX];

        // Generate a list indicating which trusted validators signed the target block. Account for
        // disorder in the validators list by iterating through all validators to match public keys and
        // signed status.
        for i in 0..VALIDATOR_SET_SIZE_MAX {
            let signed_target_header = validators[i].signed;

            // For each target validator i that has signed, if a trusted validator j has the same pubkey,
            // set the flag of trusted validator j to true.
            for j in 0..VALIDATOR_SET_SIZE_MAX {
                let pubkeys_match = self.is_equal(
                    validators[i].pubkey.clone(),
                    trusted_validator_hash_fields[j].pubkey.clone(),
                );

                let signed_target_header_and_pubkey_match =
                    self.and(pubkeys_match, signed_target_header);

                trusted_validator_signed_on_target_header[j] = self.select(
                    signed_target_header_and_pubkey_match,
                    true_var,
                    trusted_validator_signed_on_target_header[j],
                );
            }
        }

        let trusted_vp = trusted_validator_hash_fields
            .as_vec()
            .iter()
            .map(|v| v.voting_power)
            .collect::<Vec<_>>();

        // Assert validators marked as signed from the target block comprise > 1/3 of the voting
        // power on the trusted block.
        let threshold_numerator = self.constant::<U64Variable>(1);
        let threshold_denominator = self.constant::<U64Variable>(3);
        self.verify_voting_threshold::<VALIDATOR_SET_SIZE_MAX>(
            &trusted_vp,
            trusted_nb_enabled_validators,
            &threshold_numerator,
            &threshold_denominator,
            &trusted_validator_signed_on_target_header,
        );
    }

    fn verify_voting_threshold<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        validator_voting_power: &[U64Variable],
        nb_enabled_validators: Variable,
        threshold_numerator: &U64Variable,
        threshold_denominator: &U64Variable,
        include_in_check: &[BoolVariable],
    ) {
        assert_eq!(validator_voting_power.len(), include_in_check.len());

        // Compute the total voting power of the entire validator set.
        let total_voting_power = self.get_total_voting_power::<VALIDATOR_SET_SIZE_MAX>(
            validator_voting_power,
            nb_enabled_validators,
        );

        // Compute whether the voting power of the included validators is greater than the threshold.
        let gt_threshold = self.is_voting_power_greater_than_threshold::<VALIDATOR_SET_SIZE_MAX>(
            validator_voting_power,
            include_in_check,
            &total_voting_power,
            threshold_numerator,
            threshold_denominator,
        );

        // Assert the voting power of the included validators is greater than the threshold.
        let true_v = self._true();
        self.assert_is_equal(gt_threshold, true_v);
    }

    fn verify_step<const VALIDATOR_SET_SIZE_MAX: usize, const CHAIN_ID_SIZE_BYTES: usize>(
        &mut self,
        expected_chain_id_bytes: &[u8],
        prev_block_number: U64Variable,
        prev_header_hash: Bytes32Variable,
        step: &VerifyStepVariable<VALIDATOR_SET_SIZE_MAX>,
    ) {
        let one = self.one();
        let next_block = self.add(prev_block_number, one);
        // Verify the new Tendermint consensus block.
        self.verify_header::<VALIDATOR_SET_SIZE_MAX, CHAIN_ID_SIZE_BYTES>(
            expected_chain_id_bytes,
            &step.next_block_validators,
            step.next_block_nb_validators,
            &step.next_header,
            &next_block,
            &step.next_header_chain_id_proof,
            &step.next_header_height_proof,
            &step.next_header_validators_hash_proof,
            &step.next_block_round,
        );

        // Verify the previous header hash in the new header matches the previous header.
        self.verify_prev_header_in_header(
            &step.next_header,
            prev_header_hash,
            &step.next_header_last_block_id_proof,
        );

        // Verify the next validators hash in the previous block matches the new validators hash.
        let new_validators_hash: Bytes32Variable =
            step.next_header_validators_hash_proof.leaf[2..2 + HASH_SIZE].into();
        self.verify_prev_header_next_validators_hash(
            new_validators_hash,
            &prev_header_hash,
            &step.prev_header_next_validators_hash_proof,
        );
    }

    fn verify_skip_distance(
        &mut self,
        skip_max: usize,
        trusted_block: &U64Variable,
        target_block: &U64Variable,
    ) {
        let true_v = self._true();
        let one = self.one();
        let trusted_block_plus_one = self.add(*trusted_block, one);
        // Verify target block > trusted block.
        let is_target_gt_trusted = self.gt(*target_block, trusted_block_plus_one);
        self.assert_is_equal(is_target_gt_trusted, true_v);

        let skip_max_var = self.constant::<U64Variable>(skip_max as u64);
        let max_block = self.add(*trusted_block, skip_max_var);
        // Verify target block <= trusted block + skip_max.
        let is_target_lte_skip_max = self.lte(*target_block, max_block);
        self.assert_is_equal(is_target_lte_skip_max, true_v);
    }

    fn verify_skip<const VALIDATOR_SET_SIZE_MAX: usize, const CHAIN_ID_SIZE_BYTES: usize>(
        &mut self,
        expected_chain_id_bytes: &[u8],
        skip_max: usize,
        trusted_block: U64Variable,
        trusted_header_hash: Bytes32Variable,
        target_block: U64Variable,
        skip: &VerifySkipVariable<VALIDATOR_SET_SIZE_MAX>,
    ) {
        // Verify the target block is non-sequential with the trusted block and within maximum
        // skip distance.
        self.verify_skip_distance(skip_max, &trusted_block, &target_block);

        // Verify the set of validators who've signed on the commit from the target block comprise
        // more than 1/3 of the voting power on the trusted block.
        self.verify_trusted_validators(
            &skip.target_block_validators,
            trusted_header_hash,
            &skip.trusted_header_validator_hash_proof,
            &skip.trusted_header_validator_hash_fields,
            skip.trusted_block_nb_validators,
        );

        // Verify the target Tendermint consensus block.
        self.verify_header::<VALIDATOR_SET_SIZE_MAX, CHAIN_ID_SIZE_BYTES>(
            expected_chain_id_bytes,
            &skip.target_block_validators,
            skip.target_block_nb_validators,
            &skip.target_header,
            &target_block,
            &skip.target_header_chain_id_proof,
            &skip.target_header_height_proof,
            &skip.target_header_validator_hash_proof,
            &skip.target_block_round,
        );
    }
}

// To run tests with logs (i.e. to see proof generation time), set the environment variable `RUST_LOG=debug` before the test command.
// Alternatively, add env::set_var("RUST_LOG", "debug") to the top of the test.
#[cfg(test)]
pub(crate) mod tests {

    use ethers::types::H256;
    use plonky2x::prelude::DefaultBuilder;
    use subtle_encoding::hex;

    use super::*;

    #[test]
    fn test_verify_hash_in_message() {
        // This is a test case generated from block 144094 of Celestia's Mocha 3 testnet
        // Block Hash: 8909e1b73b7d987e95a7541d96ed484c17a4b0411e98ee4b7c890ad21302ff8c (needs to be lower case)
        // Signed Message (from the last validator): 6b080211de3202000000000022480a208909e1b73b7d987e95a7541d96ed484c17a4b0411e98ee4b7c890ad21302ff8c12240801122061263df4855e55fcab7aab0a53ee32cf4f29a1101b56de4a9d249d44e4cf96282a0b089dce84a60610ebb7a81932076d6f6368612d33
        // No round exists in the message that was signed above.

        env_logger::try_init().unwrap_or_default();

        // Define the circuit
        let mut builder = DefaultBuilder::new();
        let message = builder.read::<ValidatorMessageVariable>();
        let header_hash = builder.read::<TendermintHashVariable>();
        let round = builder.read::<U64Variable>();

        let verified = builder.verify_hash_in_message(&message, header_hash, round);

        builder.write(verified);
        let circuit = builder.build();

        let header_hash =
            hex::decode("8909e1b73b7d987e95a7541d96ed484c17a4b0411e98ee4b7c890ad21302ff8c")
                .unwrap();
        let header_hash_h256 = H256::from_slice(&header_hash);
        let mut signed_message = hex::decode("6b080211de3202000000000022480a208909e1b73b7d987e95a7541d96ed484c17a4b0411e98ee4b7c890ad21302ff8c12240801122061263df4855e55fcab7aab0a53ee32cf4f29a1101b56de4a9d249d44e4cf96282a0b089dce84a60610ebb7a81932076d6f6368612d33").unwrap();
        signed_message.resize(VALIDATOR_MESSAGE_BYTES_LENGTH_MAX, 0u8);
        let mut input = circuit.input();
        input.write::<ValidatorMessageVariable>(signed_message.try_into().unwrap());
        input.write::<TendermintHashVariable>(header_hash_h256);
        input.write::<U64Variable>(0u64);
        let (_, mut output) = circuit.prove(&input);
        let verified = output.read::<BoolVariable>();
        assert!(verified);
    }

    // TODO: Add test for verifying validator signatures from a commit that has round != 0.
}
