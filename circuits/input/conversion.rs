use ethers::types::U256;
use plonky2x::frontend::curta::ec::point::CompressedEdwardsY;
use plonky2x::frontend::ecc::curve25519::ed25519::eddsa::{
    EDDSASignatureVariableValue, DUMMY_PUBLIC_KEY, DUMMY_SIGNATURE,
};
use plonky2x::prelude::RichField;
use tendermint::block::signed_header::SignedHeader;
use tendermint::block::{Commit, CommitSig};
use tendermint::chain::Id;
use tendermint::crypto::default::signature::Verifier;
use tendermint::crypto::signature::Verifier as _;
use tendermint::validator::{Info, Set as TendermintValidatorSet};
use tendermint::vote::{SignedVote, ValidatorIndex};
use tendermint::PublicKey;

use super::tendermint_utils::get_vote_from_commit_sig;
use crate::consts::{VALIDATOR_BYTE_LENGTH_MAX, VALIDATOR_MESSAGE_BYTES_LENGTH_MAX};
use crate::variables::*;

/// Get the padded_message, message_length, and signature for the validator from a specific
/// commit signature.
fn get_signed_message_data<F: RichField>(
    chain_id: &Id,
    pubkey: &PublicKey,
    commit_sig: &CommitSig,
    val_idx: &ValidatorIndex,
    commit: &Commit,
) -> (
    [u8; VALIDATOR_MESSAGE_BYTES_LENGTH_MAX],
    usize,
    EDDSASignatureVariableValue<F>,
) {
    let vote = get_vote_from_commit_sig(commit_sig, *val_idx, commit).unwrap();
    let signed_vote =
        SignedVote::from_vote(vote.clone(), chain_id.clone()).expect("missing signature");
    let mut padded_signed_message = signed_vote.sign_bytes();
    let msg_length = padded_signed_message.len();

    padded_signed_message.resize(VALIDATOR_MESSAGE_BYTES_LENGTH_MAX, 0u8);

    let sig = signed_vote.signature();

    let signature_value = EDDSASignatureVariableValue {
        r: CompressedEdwardsY(sig.as_bytes()[0..32].try_into().unwrap()),
        s: U256::from_little_endian(&sig.as_bytes()[32..64]),
    };

    Verifier::verify(*pubkey, &signed_vote.sign_bytes(), sig)
        .expect("Signature should be valid for validator");

    (
        padded_signed_message.try_into().unwrap(),
        msg_length,
        signature_value,
    )
}

/// Get the validator data for a specific block.
pub fn get_validator_data_from_block<const VALIDATOR_SET_SIZE_MAX: usize, F: RichField>(
    block_validators: &[Info],
    signed_header: &SignedHeader,
) -> Vec<ValidatorType<F>> {
    let mut validators = Vec::new();

    // Signatures or dummy
    // Need signature to output either verify or no verify (then we can assert that it matches or doesn't match)
    let validator_set = TendermintValidatorSet::new(block_validators.to_vec(), None);

    // Exclude invalid validators (i.e. those that are malformed & are not included in the validator set).
    for i in 0..signed_header.commit.signatures.len() {
        let validator = Box::new(match validator_set.validator(block_validators[i].address) {
            Some(validator) => validator,
            None => continue, // Cannot find matching validator, so we skip the vote
        });
        let val_bytes = validator.hash_bytes();
        let val_idx = ValidatorIndex::try_from(i).unwrap();
        let pubkey = CompressedEdwardsY::from_slice(&validator.pub_key.to_bytes()).unwrap();

        if signed_header.commit.signatures[i].is_commit() {
            // Get the padded_message, message_length, and signature for the validator.
            let (padded_msg, msg_length, signature) = get_signed_message_data(
                &signed_header.header.chain_id,
                &validator.pub_key,
                &signed_header.commit.signatures[i],
                &val_idx,
                &signed_header.commit,
            );

            validators.push(ValidatorType {
                pubkey,
                signature,
                message: padded_msg,
                message_byte_length: F::from_canonical_usize(msg_length),
                voting_power: validator.power(),
                validator_byte_length: F::from_canonical_usize(val_bytes.len()),
                signed: true,
            });
        } else {
            let signature_value = EDDSASignatureVariableValue {
                r: CompressedEdwardsY(DUMMY_SIGNATURE[0..32].try_into().unwrap()),
                s: U256::from_little_endian(&DUMMY_SIGNATURE[32..64]),
            };

            // These are dummy signatures (included in val hash, did not vote)
            validators.push(ValidatorType {
                pubkey,
                signature: signature_value,
                message: [0u8; VALIDATOR_MESSAGE_BYTES_LENGTH_MAX],
                message_byte_length: F::from_canonical_usize(32),
                voting_power: validator.power(),
                validator_byte_length: F::from_canonical_usize(val_bytes.len()),
                signed: false,
            });
        }
    }

    // These are empty signatures (not included in val hash)
    for _ in signed_header.commit.signatures.len()..VALIDATOR_SET_SIZE_MAX {
        let pubkey = CompressedEdwardsY::from_slice(&DUMMY_PUBLIC_KEY).unwrap();
        let signature_value = EDDSASignatureVariableValue {
            r: CompressedEdwardsY(DUMMY_SIGNATURE[0..32].try_into().unwrap()),
            s: U256::from_little_endian(&DUMMY_SIGNATURE[32..64]),
        };

        validators.push(ValidatorType {
            pubkey,
            signature: signature_value,
            message: [0u8; VALIDATOR_MESSAGE_BYTES_LENGTH_MAX],
            message_byte_length: F::from_canonical_usize(32),
            voting_power: 0u64,
            validator_byte_length: F::from_canonical_usize(VALIDATOR_BYTE_LENGTH_MAX),
            signed: false,
        });
    }

    validators
}

pub fn validator_hash_field_from_block<const VALIDATOR_SET_SIZE_MAX: usize, F: RichField>(
    trusted_validator_set: &[Info],
    trusted_commit: &Commit,
) -> Vec<ValidatorHashField<F>> {
    let mut trusted_validator_fields = Vec::new();

    let validator_set = TendermintValidatorSet::new(trusted_validator_set.to_vec(), None);

    let block_validators = validator_set.validators();

    for i in 0..trusted_commit.signatures.len() {
        let validator = Box::new(match validator_set.validator(block_validators[i].address) {
            Some(validator) => validator,
            None => continue, // Cannot find matching validator, so we skip the vote
        });
        let val_bytes = validator.hash_bytes();
        let pubkey = CompressedEdwardsY::from_slice(&validator.pub_key.to_bytes()).unwrap();

        trusted_validator_fields.push(ValidatorHashField {
            pubkey,
            voting_power: validator.power(),
            validator_byte_length: F::from_canonical_usize(val_bytes.len()),
        });
    }

    let val_so_far = trusted_validator_fields.len();

    // These are empty signatures (not included in val hash)
    for _ in val_so_far..VALIDATOR_SET_SIZE_MAX {
        let pubkey = CompressedEdwardsY::from_slice(&DUMMY_PUBLIC_KEY).unwrap();

        trusted_validator_fields.push(ValidatorHashField {
            pubkey,
            voting_power: 0u64,
            validator_byte_length: F::from_canonical_usize(VALIDATOR_BYTE_LENGTH_MAX),
        });
    }

    trusted_validator_fields
}
