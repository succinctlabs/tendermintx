use num::BigUint;
use plonky2x::frontend::ecc::ed25519::curve::curve_types::AffinePoint;
pub use plonky2x::frontend::ecc::ed25519::curve::ed25519::Ed25519;
pub use plonky2x::frontend::ecc::ed25519::field::ed25519_scalar::Ed25519Scalar;
use plonky2x::frontend::ecc::ed25519::gadgets::curve::AffinePointTarget;
use plonky2x::frontend::ecc::ed25519::gadgets::eddsa::EDDSASignatureTarget;
use plonky2x::frontend::merkle::tree::MerkleInclusionProofVariable;
use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::frontend::vars::U32Variable;
use plonky2x::prelude::{
    ArrayVariable, BoolVariable, Bytes32Variable, BytesVariable, CircuitBuilder, CircuitVariable,
    Field, PlonkParameters, RichField, Variable,
};
use tendermint::crypto::ed25519::VerificationKey;
use tendermint::Signature;

use crate::consts::{
    HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES, PROTOBUF_HASH_SIZE_BYTES,
    VALIDATOR_BYTE_LENGTH_MAX, VALIDATOR_MESSAGE_BYTES_LENGTH_MAX,
};

pub type EDDSAPublicKeyVariable = AffinePointTarget<Ed25519>;
pub type EDDSAPublicKeyValueType<F> = <EDDSAPublicKeyVariable as CircuitVariable>::ValueType<F>;

// Converts a public key to an AffinePoint<Ed25519>, which is the value type of EDDSAPublicKeyVariable
pub fn pubkey_to_value_type<F: RichField>(pubkey: &VerificationKey) -> EDDSAPublicKeyValueType<F> {
    let pubkey_bytes = pubkey.as_bytes();
    AffinePoint::new_from_compressed_point(pubkey_bytes)
}

pub type EDDSASignatureVariable = EDDSASignatureTarget<Ed25519>;
pub type EDDSASignatureValueType<F> = <EDDSASignatureVariable as CircuitVariable>::ValueType<F>;

// Converts a signature to the value type of EDDSASignatureVariable
pub fn signature_to_value_type<F: RichField>(signature: &Signature) -> EDDSASignatureValueType<F> {
    let sig_bytes = signature.as_bytes();
    let sig_r = AffinePoint::new_from_compressed_point(&sig_bytes[0..32]);
    assert!(sig_r.is_valid());
    let sig_s_biguint = BigUint::from_bytes_le(&sig_bytes[32..64]);
    if sig_s_biguint.to_u32_digits().is_empty() {
        panic!("sig_s_biguint has 0 limbs which will cause problems down the line")
    }
    let sig_s = Ed25519Scalar::from_noncanonical_biguint(sig_s_biguint);
    EDDSASignatureValueType::<F> { r: sig_r, s: sig_s }
}

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
    pub pubkey: EDDSAPublicKeyVariable,
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
    pub pubkey: EDDSAPublicKeyVariable,
    pub voting_power: U64Variable,
    pub validator_byte_length: Variable,
    pub enabled: BoolVariable,
}
