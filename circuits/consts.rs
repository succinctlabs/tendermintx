pub use tendermint::merkle::HASH_SIZE;

/// The number of validators on the Tendermint chain.
pub const VALIDATOR_SET_SIZE_MAX: usize = 100;

/// The maximum number of bytes in a protobuf-encoded chain ID. The maximum chain ID length is
/// 50 characters + 2 bytes for the encoding prefix. Source:
/// https://docs.tendermint.com/v0.34/tendermint-core/using-tendermint.html#fields
pub const PROTOBUF_CHAIN_ID_SIZE_BYTES: usize = 52;

/// The number of bytes in a protobuf-encoded SHA256 hash.
pub const PROTOBUF_HASH_SIZE_BYTES: usize = HASH_SIZE + 2;

/// The number of bytes in a protobuf-encoded tendermint block ID.
pub const PROTOBUF_BLOCK_ID_SIZE_BYTES: usize = 72;

/// Depth of the proofs against the header.
pub const HEADER_PROOF_DEPTH: usize = 4;

/// The maximum length of a protobuf-encoded Tendermint validator in bytes.
pub const VALIDATOR_BYTE_LENGTH_MAX: usize = 46;

/// The maximum number of bytes in a protobuf-encoded varint.
/// https://docs.tendermint.com/v0.34/tendermint-core/using-tendermint.html#tendermint-networks
pub const VARINT_BYTES_LENGTH_MAX: usize = 9;
pub const PROTOBUF_VARINT_SIZE_BYTES: usize = VARINT_BYTES_LENGTH_MAX + 1;

/// The maximum number of bytes in a validator message (CanonicalVote toSignBytes).
pub const VALIDATOR_MESSAGE_BYTES_LENGTH_MAX: usize = 168;

// Header indices for the Merkle tree.
pub const CHAIN_ID_INDEX: usize = 1;
pub const BLOCK_HEIGHT_INDEX: usize = 2;
pub const LAST_BLOCK_ID_INDEX: usize = 4;
pub const DATA_HASH_INDEX: usize = 6;
pub const VALIDATORS_HASH_INDEX: usize = 7;
pub const NEXT_VALIDATORS_HASH_INDEX: usize = 8;
