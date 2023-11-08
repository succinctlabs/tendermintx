use ethers::types::U256;
use plonky2x::frontend::curta::ec::point::CompressedEdwardsY;
use plonky2x::frontend::ecc::curve25519::ed25519::eddsa::{
    EDDSASignatureVariableValue, DUMMY_PUBLIC_KEY, DUMMY_SIGNATURE,
};
use plonky2x::prelude::RichField;
use tendermint::crypto::default::signature::Verifier;
use tendermint::crypto::signature::Verifier as _;
use tendermint::validator::Set as ValidatorSet;
use tendermint::vote::{SignedVote, ValidatorIndex};

use super::tendermint_utils::{non_absent_vote, SignedBlock};
use crate::consts::{VALIDATOR_BYTE_LENGTH_MAX, VALIDATOR_MESSAGE_BYTES_LENGTH_MAX};
use crate::variables::*;

pub fn validators_from_block<const VALIDATOR_SET_SIZE_MAX: usize, F: RichField>(
    block: &SignedBlock,
) -> Vec<Validator<F>> {
    let mut validators = Vec::new();

    // Signatures or dummy
    // Need signature to output either verify or no verify (then we can assert that it matches or doesn't match)
    let validator_set = ValidatorSet::new(
        block.validator_set.validators.clone(),
        block.validator_set.proposer.clone(),
    );
    let block_validators = validator_set.validators();

    // Exclude invalid validators (i.e. those that are malformed & are not included in the validator set).
    for i in 0..block.commit.signatures.len() {
        let val_idx = ValidatorIndex::try_from(i).unwrap();
        let validator = Box::new(match validator_set.validator(block_validators[i].address) {
            Some(validator) => validator,
            None => continue, // Cannot find matching validator, so we skip the vote
        });
        let val_bytes = validator.hash_bytes();
        let pubkey =
            CompressedEdwardsY::try_from(validator.pub_key.ed25519().unwrap().as_bytes()).unwrap();

        if block.commit.signatures[i].is_commit() {
            let vote =
                non_absent_vote(&block.commit.signatures[i], val_idx, &block.commit).unwrap();

            let signed_vote = Box::new(
                SignedVote::from_vote(vote.clone(), block.header.chain_id.clone())
                    .expect("missing signature"),
            );
            let mut message_padded = signed_vote.sign_bytes();
            message_padded.resize(VALIDATOR_MESSAGE_BYTES_LENGTH_MAX, 0u8);

            let sig = signed_vote.signature();

            let signature_value = EDDSASignatureVariableValue {
                r: CompressedEdwardsY(sig.as_bytes()[0..32].try_into().unwrap()),
                s: U256::from_little_endian(&sig.as_bytes()[32..64]),
            };

            // Source: https://github.com/informalsystems/tendermint-rs/blob/bcc0b377812b8e53a02dff156988569c5b3c81a2/tendermint/src/crypto/default/signature.rs#L199-L200
            Verifier::verify(validator.pub_key, &signed_vote.sign_bytes(), sig)
                .unwrap_or_else(|_| panic!("signature should be valid for validator {}", i));

            validators.push(Validator {
                pubkey,
                signature: signature_value,
                message: message_padded.try_into().unwrap(),
                message_byte_length: F::from_canonical_usize(signed_vote.sign_bytes().len()),
                voting_power: validator.power(),
                validator_byte_length: F::from_canonical_usize(val_bytes.len()),
                enabled: true,
                signed: true,
                present_on_trusted_header: false,
            });
        } else {
            let signature_value = EDDSASignatureVariableValue {
                r: CompressedEdwardsY(DUMMY_SIGNATURE[0..32].try_into().unwrap()),
                s: U256::from_little_endian(&DUMMY_SIGNATURE[32..64]),
            };

            // These are dummy signatures (included in val hash, did not vote)
            validators.push(Validator {
                pubkey,
                signature: signature_value,
                message: [0u8; VALIDATOR_MESSAGE_BYTES_LENGTH_MAX],
                message_byte_length: F::from_canonical_usize(32),
                voting_power: validator.power(),
                validator_byte_length: F::from_canonical_usize(val_bytes.len()),
                enabled: true,
                signed: false,
                present_on_trusted_header: false,
            });
        }
    }

    // These are empty signatures (not included in val hash)
    for _ in block.commit.signatures.len()..VALIDATOR_SET_SIZE_MAX {
        let pubkey = CompressedEdwardsY::from_slice(&DUMMY_PUBLIC_KEY).unwrap();
        let signature_value = EDDSASignatureVariableValue {
            r: CompressedEdwardsY(DUMMY_SIGNATURE[0..32].try_into().unwrap()),
            s: U256::from_little_endian(&DUMMY_SIGNATURE[32..64]),
        };

        validators.push(Validator {
            pubkey,
            signature: signature_value,
            message: [0u8; VALIDATOR_MESSAGE_BYTES_LENGTH_MAX],
            message_byte_length: F::from_canonical_usize(32),
            voting_power: 0u64,
            validator_byte_length: F::from_canonical_usize(VALIDATOR_BYTE_LENGTH_MAX),
            enabled: false,
            signed: false,
            present_on_trusted_header: false, // This field ignored for this case
        });
    }

    validators
}

pub fn validator_hash_field_from_block<const VALIDATOR_SET_SIZE_MAX: usize, F: RichField>(
    trusted_block: &SignedBlock,
) -> Vec<ValidatorHashField<F>> {
    let mut trusted_validator_fields = Vec::new();

    let validator_set = ValidatorSet::new(
        trusted_block.validator_set.validators.clone(),
        trusted_block.validator_set.proposer.clone(),
    );

    let block_validators = validator_set.validators();

    for i in 0..trusted_block.commit.signatures.len() {
        let validator = Box::new(match validator_set.validator(block_validators[i].address) {
            Some(validator) => validator,
            None => continue, // Cannot find matching validator, so we skip the vote
        });
        let val_bytes = validator.hash_bytes();
        let pubkey =
            CompressedEdwardsY::try_from(validator.pub_key.ed25519().unwrap().as_bytes()).unwrap();

        trusted_validator_fields.push(ValidatorHashField {
            pubkey,
            voting_power: validator.power(),
            validator_byte_length: F::from_canonical_usize(val_bytes.len()),
            enabled: true,
        });
    }

    let val_so_far = trusted_validator_fields.len();

    // These are empty signatures (not included in val hash)
    for _ in val_so_far..VALIDATOR_SET_SIZE_MAX {
        let pubkey = CompressedEdwardsY::from_slice(&DUMMY_PUBLIC_KEY).unwrap();

        // TODO: Fix empty signatures
        trusted_validator_fields.push(ValidatorHashField {
            pubkey,
            voting_power: 0u64,
            validator_byte_length: F::from_canonical_usize(VALIDATOR_BYTE_LENGTH_MAX),
            enabled: false,
        });
    }

    trusted_validator_fields
}

pub fn update_present_on_trusted_header<F: RichField>(
    target_validators: &mut [Validator<F>],
    target_block: &SignedBlock,
    start_block: &SignedBlock,
) {
    // Parse each block to compute the validators that are the same from block_1 to block_2, and the cumulative voting power of the shared validators
    let mut shared_voting_power = 0;

    let threshold = 1_f64 / 3_f64;

    let target_block_validator_set = ValidatorSet::new(
        target_block.validator_set.validators.clone(),
        target_block.validator_set.proposer.clone(),
    );
    let start_block_validator_set = ValidatorSet::new(
        start_block.validator_set.validators.clone(),
        start_block.validator_set.proposer.clone(),
    );

    let target_block_total_voting_power = target_block_validator_set.total_voting_power().value();

    let start_block_validators = start_block_validator_set.validators();

    let mut start_block_idx = 0;
    let start_block_num_validators = start_block_validators.len();

    // Exit if we have already reached the threshold
    // TODO: Confirm this is resilient by testing many different cases.
    while target_block_total_voting_power as f64 * threshold > shared_voting_power as f64
        && start_block_idx < start_block_num_validators
    {
        if let Some(target_block_validator) =
            target_block_validator_set.validator(start_block_validators[start_block_idx].address)
        {
            // Get index of start_block_validators[idx] in target_block_validators
            let target_idx = target_block_validator_set
                .validators()
                .iter()
                .position(|x| *x == target_block_validator)
                .unwrap();

            // Confirm that the validator has signed on block_2
            for sig in target_block.commit.signatures.iter() {
                if sig.validator_address().is_some()
                    && sig.validator_address().unwrap() == target_block_validator.address
                {
                    // Add the shared voting power to the validator
                    shared_voting_power += target_block_validator.power();
                    // Set the present_on_trusted_header field to true
                    target_validators[target_idx].present_on_trusted_header = true;
                    println!(
                        "updated present_on_trusted_header for target validator: {}",
                        target_idx
                    );
                }
            }
        }
        println!("start block idx: {}", start_block_idx);
        start_block_idx += 1;
    }

    assert!(
        target_block_total_voting_power as f64 * threshold <= shared_voting_power as f64,
        "shared voting power is less than threshold"
    );
}
