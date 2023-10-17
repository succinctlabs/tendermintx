pub use tendermint::merkle::HASH_SIZE;
/// The number of bits in a SHA256 hash.
pub const HASH_SIZE_BITS: usize = HASH_SIZE * 8;

/// The number of bytes in a varint.
pub const VARINT_SIZE_BYTES: usize = 9;
pub const PROTOBUF_VARINT_SIZE_BYTES: usize = VARINT_SIZE_BYTES + 1;

/// The number of bits in a protobuf-encoded SHA256 hash.
pub const PROTOBUF_HASH_SIZE_BYTES: usize = HASH_SIZE + 2;

/// The number of bits in a protobuf-encoded tendermint block ID.
pub const PROTOBUF_BLOCK_ID_SIZE_BYTES: usize = 72;

// Constants that represent the number of bytes necessary to pad the protobuf encoded data for SHA256
pub const PROTOBUF_HASH_SHA256_NUM_BYTES: usize = 64;
pub const PROTOBUF_BLOCK_ID_SHA256_NUM_BYTES: usize = 128;

// Depth of the proofs against the header.
pub const HEADER_PROOF_DEPTH: usize = 4;

/// The maximum length of a protobuf-encoded Tendermint validator in bytes.
pub const VALIDATOR_BYTE_LENGTH_MAX: usize = 46;

/// The minimum length of a protobuf-encoded Tendermint validator in bytes.
pub const VALIDATOR_BYTE_LENGTH_MIN: usize = 38;

/// The number of possible byte lengths of a protobuf-encoded Tendermint validator.
pub const NUM_POSSIBLE_VALIDATOR_BYTE_LENGTHS: usize =
    VALIDATOR_BYTE_LENGTH_MAX - VALIDATOR_BYTE_LENGTH_MIN + 1;

// The maximum number of bytes in a protobuf-encoded varint.
// https://docs.tendermint.com/v0.34/tendermint-core/using-tendermint.html#tendermint-networks
pub const VARINT_BYTES_LENGTH_MAX: usize = 9;

// The maximum number of bytes in a validator message (CanonicalVote toSignBytes).
pub const VALIDATOR_MESSAGE_BYTES_LENGTH_MAX: usize = 124;

// The number of bytes in an encoded data root tuple.
pub const ENC_DATA_ROOT_TUPLE_SIZE_BYTES: usize = 64;

// Header indexes for the Merkle tree.
pub const BLOCK_HEIGHT_INDEX: usize = 2;
pub const LAST_BLOCK_ID_INDEX: usize = 4;
pub const DATA_HASH_INDEX: usize = 6;
pub const VALIDATORS_HASH_INDEX: usize = 7;
pub const NEXT_VALIDATORS_HASH_INDEX: usize = 8;
