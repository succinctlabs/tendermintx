use plonky2x::frontend::curta::ec::point::CompressedEdwardsYVariable;
use plonky2x::frontend::ecc::curve25519::ed25519::eddsa::EDDSASignatureVariable;
use plonky2x::frontend::merkle::tree::MerkleInclusionProofVariable;
use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::frontend::vars::{ByteVariable, U32Variable};
use plonky2x::prelude::{
    ArrayVariable, BoolVariable, Bytes32Variable, BytesVariable, CircuitBuilder, CircuitVariable,
    PlonkParameters, RichField, Variable,
};

use crate::consts::{
    HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES, PROTOBUF_CHAIN_ID_SIZE_BYTES,
    PROTOBUF_HASH_SIZE_BYTES, VALIDATOR_BYTE_LENGTH_MAX, VALIDATOR_MESSAGE_BYTES_LENGTH_MAX,
};

/// A protobuf-encoded tendermint block ID as a 72 byte target.
pub type EncBlockIDVariable = BytesVariable<PROTOBUF_BLOCK_ID_SIZE_BYTES>;

// A protobuf-encoded tendermint hash as a 34 byte target.
pub type EncTendermintHashVariable = BytesVariable<PROTOBUF_HASH_SIZE_BYTES>;

/// The Tendermint hash as a 32 byte variable.
pub type TendermintHashVariable = Bytes32Variable;

/// The marshalled validator bytes as a variable.
pub type MarshalledValidatorVariable = BytesVariable<VALIDATOR_BYTE_LENGTH_MAX>;

/// The message signed by the validator as a variable.
pub type ValidatorMessageVariable = BytesVariable<VALIDATOR_MESSAGE_BYTES_LENGTH_MAX>;

// A chain id proof as a struct.
// Proof is the chain id proof against a header.
// ChainID is the chain id of the header as bytes.
// EncChainIdByteLength is the length of the protobuf-encoded chain id as a u32.
#[derive(Clone, Debug, CircuitVariable)]
#[value_name(ChainIdProofValueType)]
pub struct ChainIdProofVariable {
    pub proof: ArrayVariable<Bytes32Variable, HEADER_PROOF_DEPTH>,
    pub enc_chain_id_byte_length: U32Variable,
    pub chain_id: ArrayVariable<ByteVariable, PROTOBUF_CHAIN_ID_SIZE_BYTES>,
}

// A block height proof as a struct.
// Proof is the block height proof against a header.
// Height is the block height of the header as a u64.
// EncHeightByteLength is the length of the protobuf-encoded height as a u32.
// The reason we cannot use a MerkleInclusionProofVariable is the height is not fixed length
// and the encoding of the height is not fixed length.
#[derive(Clone, Debug, CircuitVariable)]
#[value_name(HeightProofValueType)]
pub struct HeightProofVariable {
    pub proof: ArrayVariable<Bytes32Variable, HEADER_PROOF_DEPTH>,
    pub enc_height_byte_length: U32Variable,
    pub height: U64Variable,
}

/// The protobuf-encoded leaf (a hash), and it's corresponding proof and path indices against the header.
pub type HashInclusionProofVariable =
    MerkleInclusionProofVariable<HEADER_PROOF_DEPTH, PROTOBUF_HASH_SIZE_BYTES>;

pub type BlockIDInclusionProofVariable =
    MerkleInclusionProofVariable<HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES>;

/// A validator is a struct containing the pubkey, signature, message, message byte length, voting
/// power, validator byte length, and three flags: enabled, signed, and present_on_trusted_header.
///
/// A validator is marked as enabled if it is a part of the validator set for the specified block.
/// A validator is marked as signed if it has signed the block. A validator is marked as present on
/// trusted header if it is a part of the validator set for the trusted header (only used in skip).
#[derive(Debug, Clone, CircuitVariable)]
#[value_name(ValidatorType)]
pub struct ValidatorVariable {
    pub pubkey: CompressedEdwardsYVariable,
    pub signature: EDDSASignatureVariable,
    pub message: ValidatorMessageVariable,
    pub message_byte_length: Variable,
    pub voting_power: U64Variable,
    pub validator_byte_length: Variable,
    pub signed: BoolVariable,
    // Only used in skip circuit.
    pub present_on_trusted_header: BoolVariable,
}

/// A validator hash field is a struct containing the pubkey, voting power, validator byte length,
/// and enabled flag of a validator. A validator is marked as enabled if it is a part of the
/// validator set for the specified block height.
#[derive(Debug, Clone, CircuitVariable)]
#[value_name(ValidatorHashField)]
pub struct ValidatorHashFieldVariable {
    pub pubkey: CompressedEdwardsYVariable,
    pub voting_power: U64Variable,
    pub validator_byte_length: Variable,
}

/// Inputs to verify_skip circuit.
#[derive(Debug, Clone, CircuitVariable)]
#[value_name(VerifySkipStruct)]
pub struct VerifySkipVariable<const MAX_VALIDATOR_SET_SIZE: usize> {
    pub target_header: TendermintHashVariable,
    pub target_block: U64Variable,
    pub target_block_validators: ArrayVariable<ValidatorVariable, MAX_VALIDATOR_SET_SIZE>,
    pub target_block_nb_validators: Variable,
    pub target_block_round: U64Variable,
    pub target_header_chain_id_proof: ChainIdProofVariable,
    pub target_header_height_proof: HeightProofVariable,
    pub target_header_validator_hash_proof: HashInclusionProofVariable,
    pub trusted_header: TendermintHashVariable,
    pub trusted_block: U64Variable,
    pub trusted_block_nb_validators: Variable,
    pub trusted_header_validator_hash_proof: HashInclusionProofVariable,
    pub trusted_header_validator_hash_fields:
        ArrayVariable<ValidatorHashFieldVariable, MAX_VALIDATOR_SET_SIZE>,
}

/// Inputs to verify_step circuit.
#[derive(Debug, Clone, CircuitVariable)]
#[value_name(VerifyStepStruct)]
pub struct VerifyStepVariable<const MAX_VALIDATOR_SET_SIZE: usize> {
    pub next_header: Bytes32Variable,
    pub next_block: U64Variable,
    pub next_block_validators: ArrayVariable<ValidatorVariable, MAX_VALIDATOR_SET_SIZE>,
    pub next_block_nb_validators: Variable,
    pub next_block_round: U64Variable,
    pub next_header_chain_id_proof: ChainIdProofVariable,
    pub next_header_height_proof: HeightProofVariable,
    pub next_header_validators_hash_proof: HashInclusionProofVariable,
    pub next_header_last_block_id_proof: BlockIDInclusionProofVariable,
    pub prev_header: Bytes32Variable,
    pub prev_header_next_validators_hash_proof: HashInclusionProofVariable,
}
