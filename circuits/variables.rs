use plonky2x::frontend::curta::ec::point::CompressedEdwardsYVariable;
use plonky2x::frontend::ecc::curve25519::ed25519::eddsa::EDDSASignatureVariable;
use plonky2x::frontend::merkle::tree::MerkleInclusionProofVariable;
use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::frontend::vars::U32Variable;
use plonky2x::prelude::{
    ArrayVariable, BoolVariable, Bytes32Variable, BytesVariable, CircuitBuilder, CircuitVariable,
    PlonkParameters, RichField, Variable,
};

use crate::consts::{
    HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES, PROTOBUF_HASH_SIZE_BYTES,
    VALIDATOR_BYTE_LENGTH_MAX, VALIDATOR_MESSAGE_BYTES_LENGTH_MAX,
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
#[value_name(Validator)]
pub struct ValidatorVariable {
    pub pubkey: CompressedEdwardsYVariable,
    pub signature: EDDSASignatureVariable,
    pub message: ValidatorMessageVariable,
    pub message_byte_length: Variable,
    pub voting_power: U64Variable,
    pub validator_byte_length: Variable,
    pub enabled: BoolVariable,
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
    pub enabled: BoolVariable,
}
