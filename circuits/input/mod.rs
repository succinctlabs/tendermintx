pub mod conversion;
pub mod tendermint_utils;
pub mod utils;

use std::collections::HashMap;
use std::path::Path;
use std::{env, fs};

use ethers::types::H256;
use log::{debug, info};
use plonky2x::frontend::merkle::tree::InclusionProof;
use plonky2x::prelude::RichField;
use tendermint::block::signed_header::SignedHeader;
use tendermint::validator::{Info, Set as TendermintValidatorSet};
use tendermint_proto::types::BlockId as RawBlockId;
use tendermint_proto::Protobuf;

use self::conversion::update_present_on_trusted_header;
use self::tendermint_utils::{
    generate_proofs_from_header, is_valid_skip, CommitResponse, Hash, Header, Proof,
    ValidatorSetResponse,
};
use self::utils::convert_to_h256;
use crate::consts::{
    BLOCK_HEIGHT_INDEX, HEADER_PROOF_DEPTH, LAST_BLOCK_ID_INDEX, NEXT_VALIDATORS_HASH_INDEX,
    PROTOBUF_BLOCK_ID_SIZE_BYTES, PROTOBUF_HASH_SIZE_BYTES, VALIDATORS_HASH_INDEX,
};
use crate::input::conversion::{get_validator_data_from_block, validator_hash_field_from_block};
use crate::variables::*;

#[derive(Debug, PartialEq)]
pub enum InputDataMode {
    Rpc,
    Fixture,
}

pub struct InputDataFetcher {
    pub mode: InputDataMode,
    pub url: String,
    pub fixture_path: String,
    pub proof_cache: HashMap<Hash, Vec<Proof>>,
    pub save: bool,
}

impl Default for InputDataFetcher {
    fn default() -> Self {
        dotenv::dotenv().ok();

        let url = env::var("TENDERMINT_RPC_URL").expect("TENDERMINT_RPC_URL is not set in .env");

        Self::new(&url, "./circuits/fixtures/mocha-4")
    }
}

impl InputDataFetcher {
    pub fn new(url: &str, fixture_path: &str) -> Self {
        #[allow(unused_mut)]
        let mut mode;
        #[cfg(test)]
        {
            mode = InputDataMode::Fixture;
        }
        #[cfg(not(test))]
        {
            mode = InputDataMode::Rpc;
        }

        Self {
            mode,
            url: url.to_string(),
            fixture_path: fixture_path.to_string(),
            proof_cache: HashMap::new(),
            save: false,
        }
    }

    pub fn set_save(&mut self, save: bool) {
        self.save = save;
    }

    // Get the latest signed header from the RPC endpoint.
    // Note: Only used in script.
    pub async fn get_latest_signed_header(&self) -> SignedHeader {
        if self.mode == InputDataMode::Rpc {
            let query_url = format!("{}/commit", self.url);
            let res = reqwest::get(query_url).await.unwrap().text().await.unwrap();
            let v: CommitResponse = serde_json::from_str(&res).expect("Failed to parse JSON");
            v.result.signed_header
        } else {
            panic!("get_latest_signed_header is only supported in RPC mode")
        }
    }

    // Search to find the highest block number to call request_combined_skip on. If the search
    // returns start_block + 1, then we call request_combined_step instead.
    pub async fn find_block_to_request(&self, start_block: u64, max_end_block: u64) -> u64 {
        let mut curr_end_block = max_end_block;
        loop {
            if curr_end_block - start_block == 1 {
                return curr_end_block;
            }

            let start_block_validators = self.get_validator_set_from_number(start_block).await;
            let start_validator_set = TendermintValidatorSet::new(start_block_validators, None);

            let target_block_validators = self.get_validator_set_from_number(curr_end_block).await;
            let target_validator_set = TendermintValidatorSet::new(target_block_validators, None);

            let target_block_commit = self.get_signed_header_from_number(curr_end_block).await;

            if is_valid_skip(
                start_validator_set,
                target_validator_set,
                target_block_commit.commit,
            ) {
                return curr_end_block;
            }

            let mid_block = (curr_end_block + start_block) / 2;
            curr_end_block = mid_block;
        }
    }

    pub async fn get_signed_header_from_number(&self, block_number: u64) -> SignedHeader {
        let file_name = format!(
            "{}/{}/commit.json",
            self.fixture_path,
            block_number.to_string().as_str()
        );

        let fetched_result = match &self.mode {
            InputDataMode::Rpc => {
                let query_url = format!(
                    "{}/commit?height={}",
                    self.url,
                    block_number.to_string().as_str()
                );
                info!("Querying url {:?}", query_url.as_str());
                let res = reqwest::get(query_url).await.unwrap().text().await.unwrap();
                if self.save {
                    // Ensure the directory exists
                    if let Some(parent) = Path::new(&file_name).parent() {
                        fs::create_dir_all(parent).unwrap();
                    }
                    fs::write(file_name.as_str(), res.as_bytes()).expect("Unable to write file");
                }
                res
            }
            InputDataMode::Fixture => {
                let file_content = fs::read_to_string(file_name.as_str());
                info!("File name: {}", file_name.as_str());
                file_content.unwrap()
            }
        };
        let v: CommitResponse =
            serde_json::from_str(&fetched_result).expect("Failed to parse JSON");
        v.result.signed_header
    }

    pub async fn get_validator_set_from_number(&self, block_number: u64) -> Vec<Info> {
        let mut validators = Vec::new();

        let mut page_number = 1;
        let mut num_so_far = 0;
        loop {
            let fetched_result = self.fetch_validator_result(block_number, page_number).await;

            validators.extend(fetched_result.result.validators);
            // Parse count to u32.
            let parsed_count: u32 = fetched_result.result.count.parse().unwrap();
            // Parse total to u32.
            let parsed_total: u32 = fetched_result.result.total.parse().unwrap();

            num_so_far += parsed_count;
            if num_so_far >= parsed_total {
                break;
            }
            page_number += 1;
        }

        validators
    }

    async fn fetch_validator_result(
        &self,
        block_number: u64,
        page_number: u64,
    ) -> ValidatorSetResponse {
        // Check size of validator set.
        let file_name = format!(
            "{}/{}/validators_{}.json",
            self.fixture_path,
            block_number.to_string().as_str(),
            page_number
        );
        let fetched_result = match &self.mode {
            InputDataMode::Rpc => {
                let query_url = format!(
                    "{}/validators?height={}&per_page=100&page={}",
                    self.url,
                    block_number.to_string().as_str(),
                    page_number.to_string().as_str()
                );
                info!("Querying url {:?}", query_url.as_str());
                let res = reqwest::get(query_url).await.unwrap().text().await.unwrap();
                if self.save {
                    // Ensure the directory exists
                    if let Some(parent) = Path::new(&file_name).parent() {
                        fs::create_dir_all(parent).unwrap();
                    }
                    fs::write(file_name.as_str(), res.as_bytes()).expect("Unable to write file");
                }
                res
            }
            InputDataMode::Fixture => {
                let file_content = fs::read_to_string(file_name.as_str());
                info!("File name: {}", file_name.as_str());
                file_content.unwrap()
            }
        };
        let v: ValidatorSetResponse =
            serde_json::from_str(&fetched_result).expect("Failed to parse JSON");
        v
    }

    pub fn get_merkle_proof(
        &mut self,
        block_header: &Header,
        index: u64,
        encoded_leaf: Vec<u8>,
    ) -> (Vec<u8>, Vec<H256>) {
        let hash: Hash = block_header.hash().as_bytes().try_into().unwrap();
        let proofs = match self.proof_cache.get(&hash) {
            Some(proofs) => proofs.clone(),
            None => {
                let (hash, proofs) = generate_proofs_from_header(block_header);
                self.proof_cache.insert(hash, proofs.clone());
                proofs
            }
        };
        let proof = proofs[index as usize].clone();
        (encoded_leaf, convert_to_h256(proof.aunts))
    }

    pub fn get_inclusion_proof<const LEAF_SIZE_BYTES: usize, F: RichField>(
        &mut self,
        block_header: &Header,
        index: u64,
        encoded_leaf: Vec<u8>,
    ) -> InclusionProof<HEADER_PROOF_DEPTH, LEAF_SIZE_BYTES, F> {
        let (leaf, proof) = self.get_merkle_proof(block_header, index, encoded_leaf);
        InclusionProof {
            leaf: leaf.try_into().unwrap(),
            proof,
        }
    }

    pub async fn get_step_inputs<const VALIDATOR_SET_SIZE_MAX: usize, F: RichField>(
        &mut self,
        prev_block_number: u64,
        prev_header_hash: H256,
    ) -> (
        [u8; 32],
        bool,
        Vec<ValidatorType<F>>,
        InclusionProof<HEADER_PROOF_DEPTH, PROTOBUF_HASH_SIZE_BYTES, F>,
        InclusionProof<HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES, F>,
        InclusionProof<HEADER_PROOF_DEPTH, PROTOBUF_HASH_SIZE_BYTES, F>,
    ) {
        debug!("Getting step inputs");
        let prev_block_signed_header = self.get_signed_header_from_number(prev_block_number).await;
        let prev_header = prev_block_signed_header.header;
        assert_eq!(
            prev_header.hash().as_bytes(),
            prev_header_hash.as_bytes(),
            "Prev header hash 
        doesn't pass sanity check"
        );

        let next_block_signed_header = self
            .get_signed_header_from_number(prev_block_number + 1)
            .await;
        let next_block_validators = self
            .get_validator_set_from_number(prev_block_number + 1)
            .await;

        let next_block_validators = get_validator_data_from_block::<VALIDATOR_SET_SIZE_MAX, F>(
            &next_block_validators,
            &next_block_signed_header,
        );
        assert_eq!(
            next_block_validators.len(),
            VALIDATOR_SET_SIZE_MAX,
            "validator set size needs to be the provided validator_set_size_max"
        );

        let next_block_validators_hash_proof = self.get_inclusion_proof(
            &next_block_signed_header.header,
            VALIDATORS_HASH_INDEX as u64,
            next_block_signed_header.header.validators_hash.encode_vec(),
        );

        let last_block_id_hash = next_block_signed_header.header.last_block_id.unwrap().hash;
        let encoded_last_block_id = Protobuf::<RawBlockId>::encode_vec(
            next_block_signed_header
                .header
                .last_block_id
                .unwrap_or_default(),
        );
        assert_eq!(
            last_block_id_hash.as_bytes(),
            &encoded_last_block_id[2..34],
            "prev header hash doesn't pass sanity check"
        );
        let next_block_last_block_id_proof = self.get_inclusion_proof(
            &next_block_signed_header.header,
            LAST_BLOCK_ID_INDEX as u64,
            encoded_last_block_id,
        );

        let prev_block_next_validators_hash_proof = self.get_inclusion_proof(
            &prev_header,
            NEXT_VALIDATORS_HASH_INDEX as u64,
            prev_header.next_validators_hash.encode_vec(),
        );
        let round_present = next_block_signed_header.commit.round.value() != 0;
        let next_block_header = next_block_signed_header.header.hash();
        (
            next_block_header.as_bytes().try_into().unwrap(),
            round_present,
            next_block_validators,
            next_block_validators_hash_proof,
            next_block_last_block_id_proof,
            prev_block_next_validators_hash_proof,
        )
    }

    pub async fn get_skip_inputs<const VALIDATOR_SET_SIZE_MAX: usize, F: RichField>(
        &mut self,
        trusted_block_number: u64,
        trusted_block_hash: H256,
        target_block_number: u64,
    ) -> (
        Vec<ValidatorType<F>>,                                           // validators
        [u8; 32],                                                        // target_header
        bool,                                                            // round_present
        HeightProofValueType<F>, // target_block_height_proof,
        InclusionProof<HEADER_PROOF_DEPTH, PROTOBUF_HASH_SIZE_BYTES, F>, // target_header_validators_hash_proof,
        [u8; 32],                                                        // trusted_header
        InclusionProof<HEADER_PROOF_DEPTH, PROTOBUF_HASH_SIZE_BYTES, F>, // trusted_validators_hash_proof
        Vec<ValidatorHashField<F>>, // trusted_validators_hash_fields
    ) {
        let trusted_signed_header = self
            .get_signed_header_from_number(trusted_block_number)
            .await;
        let trusted_block_validator_set = self
            .get_validator_set_from_number(trusted_block_number)
            .await;
        let computed_trusted_header_hash = trusted_signed_header.header.hash();
        assert_eq!(
            computed_trusted_header_hash.as_bytes(),
            trusted_block_hash.as_bytes()
        );
        let target_signed_header = self
            .get_signed_header_from_number(target_block_number)
            .await;
        let target_block_header = target_signed_header.header.hash();
        let round_present = target_signed_header.commit.round.value() != 0;
        let target_block_validator_set = self
            .get_validator_set_from_number(target_block_number)
            .await;
        let mut target_block_validators = get_validator_data_from_block::<VALIDATOR_SET_SIZE_MAX, F>(
            &target_block_validator_set,
            &target_signed_header,
        );
        update_present_on_trusted_header(
            &mut target_block_validators,
            &target_signed_header.commit,
            &target_block_validator_set,
            &trusted_block_validator_set,
        );

        let target_block_height_proof = self.get_merkle_proof(
            &target_signed_header.header,
            BLOCK_HEIGHT_INDEX as u64,
            target_signed_header.header.height.encode_vec(),
        );

        let target_block_height_proof = HeightProofValueType::<F> {
            height: target_signed_header.header.height.value(),
            enc_height_byte_length: target_signed_header.header.height.encode_vec().len() as u32,
            proof: target_block_height_proof.1,
        };

        let target_block_validators_hash_proof = self.get_inclusion_proof(
            &target_signed_header.header,
            VALIDATORS_HASH_INDEX as u64,
            target_signed_header.header.validators_hash.encode_vec(),
        );

        let trusted_block_validator_fields =
            validator_hash_field_from_block::<VALIDATOR_SET_SIZE_MAX, F>(
                &trusted_block_validator_set,
                &trusted_signed_header.commit,
            );
        let trusted_block_validator_hash_proof = self.get_inclusion_proof(
            &trusted_signed_header.header,
            VALIDATORS_HASH_INDEX as u64,
            trusted_signed_header.header.validators_hash.encode_vec(),
        );

        (
            target_block_validators,
            target_block_header.as_bytes().try_into().unwrap(),
            round_present,
            target_block_height_proof,
            target_block_validators_hash_proof,
            trusted_block_hash.as_bytes().try_into().unwrap(),
            trusted_block_validator_hash_proof,
            trusted_block_validator_fields,
        )
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use subtle_encoding::hex;

    #[tokio::test]
    #[cfg_attr(feature = "ci", ignore)]
    async fn test_get_header() {
        let data_fetcher = super::InputDataFetcher::default();
        let signed_header = data_fetcher.get_signed_header_from_number(3000).await;
        println!(
            "Header: {:?}",
            String::from_utf8(hex::encode(signed_header.header.hash()))
        );
    }
}
