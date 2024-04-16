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

use self::tendermint_utils::{
    generate_proofs_from_header, is_valid_skip, CommitResponse, Hash, Header, Proof,
    ValidatorSetResponse,
};
use self::utils::convert_to_h256;
use crate::consts::{
    BLOCK_HEIGHT_INDEX, CHAIN_ID_INDEX, HEADER_PROOF_DEPTH, LAST_BLOCK_ID_INDEX,
    NEXT_VALIDATORS_HASH_INDEX, PROTOBUF_BLOCK_ID_SIZE_BYTES, PROTOBUF_CHAIN_ID_SIZE_BYTES,
    PROTOBUF_HASH_SIZE_BYTES, VALIDATORS_HASH_INDEX,
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
    pub urls: Vec<String>,
    pub fixture_path: String,
    pub proof_cache: HashMap<Hash, Vec<Proof>>,
    pub save: bool,
}

pub struct StepInputs<F: RichField> {
    pub next_header: [u8; 32],
    pub round: usize,
    pub next_block_validators: Vec<ValidatorType<F>>,
    pub nb_validators: usize,
    pub next_block_chain_id_proof: ChainIdProofValueType<F>,
    pub next_block_height_proof: HeightProofValueType<F>,
    pub next_block_validators_hash_proof:
        InclusionProof<HEADER_PROOF_DEPTH, PROTOBUF_HASH_SIZE_BYTES, F>,
    pub next_block_last_block_id_proof:
        InclusionProof<HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES, F>,
    pub prev_block_next_validators_hash_proof:
        InclusionProof<HEADER_PROOF_DEPTH, PROTOBUF_HASH_SIZE_BYTES, F>,
}

pub struct SkipInputs<F: RichField> {
    pub target_block_validators: Vec<ValidatorType<F>>, // validators
    pub nb_target_validators: usize,                    // nb_validators
    pub target_header: [u8; 32],                        // target_header
    pub round: usize,                                   // round
    pub target_block_chain_id_proof: ChainIdProofValueType<F>, // target_chain_id_proof,
    pub target_block_height_proof: HeightProofValueType<F>, // target_block_height_proof,
    pub target_block_validators_hash_proof:
        InclusionProof<HEADER_PROOF_DEPTH, PROTOBUF_HASH_SIZE_BYTES, F>, // target_header_validators_hash_proof,
    pub trusted_header: [u8; 32], // trusted_header
    pub trusted_block_validators_hash_proof:
        InclusionProof<HEADER_PROOF_DEPTH, PROTOBUF_HASH_SIZE_BYTES, F>, // trusted_validators_hash_proof
    pub trusted_block_validators_hash_fields: Vec<ValidatorHashField<F>>, // trusted_validators_hash_fields
    pub nb_trusted_validators: usize,                                     // nb_trusted_validators
}

impl Default for InputDataFetcher {
    fn default() -> Self {
        dotenv::dotenv().ok();

        // TENDERMINT_RPC_URL is a list of comma separated tendermint rpc urls.
        let urls = env::var("TENDERMINT_RPC_URL").expect("TENDERMINT_RPC_URL is not set in .env");

        // Split the url's by commas.
        let urls = urls
            .split(',')
            .map(|s| s.to_string())
            .collect::<Vec<String>>();
        let fixture_path = "./circuits/fixtures/mocha-4";

        Self::new(urls, fixture_path)
    }
}

const MAX_NUM_RETRIES: usize = 3;

impl InputDataFetcher {
    pub fn new(urls: Vec<String>, fixture_path: &str) -> Self {
        #[allow(unused_mut)]
        let mut mode;
        // #[cfg(test)]
        // {
        //     mode = InputDataMode::Fixture;
        // }
        // #[cfg(not(test))]
        // {
        mode = InputDataMode::Rpc;
        // }

        Self {
            mode,
            urls,
            fixture_path: fixture_path.to_string(),
            proof_cache: HashMap::new(),
            save: false,
        }
    }

    pub fn set_save(&mut self, save: bool) {
        self.save = save;
    }

    // Request data from the Tendermint RPC with quadratic backoff & multiple RPC's.
    pub async fn request_from_rpc(&self, route: &str, retries: usize) -> String {
        for _ in 0..self.urls.len() {
            let url = format!("{}/{}", self.urls[0], route);
            info!("Querying url {:?}", url.clone());
            let mut res = reqwest::get(url.clone()).await;
            let mut num_retries = 0;
            while res.is_err() && num_retries < retries {
                info!("Querying url {:?}", url.clone());
                res = reqwest::get(url.clone()).await;
                // Quadratic backoff for requests.
                tokio::time::sleep(std::time::Duration::from_secs(2u64.pow(num_retries as u32)))
                    .await;
                num_retries += 1;
            }

            if res.is_ok() {
                return res.unwrap().text().await.unwrap();
            }
        }
        panic!("Failed to fetch data from Tendermint RPC endpoint");
    }

    // Get the latest signed header from the RPC endpoint.
    // Note: Only used in script.
    pub async fn get_latest_signed_header(&mut self) -> SignedHeader {
        if self.mode == InputDataMode::Rpc {
            let route = "commit";
            let res = self.request_from_rpc(route, MAX_NUM_RETRIES).await;
            let v: CommitResponse = serde_json::from_str(&res).expect("Failed to parse JSON");
            v.result.signed_header
        } else {
            panic!("get_latest_signed_header is only supported in RPC mode")
        }
    }

    // Search to find the highest block number to call request_combined_skip on. If the search
    // returns start_block + 1, then we call request_combined_step instead.
    pub async fn find_block_to_request(&mut self, start_block: u64, max_end_block: u64) -> u64 {
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
        let query_route = format!("commit?height={}", block_number.to_string().as_str());

        let fetched_result = match &self.mode {
            InputDataMode::Rpc => {
                let res = self.request_from_rpc(&query_route, MAX_NUM_RETRIES).await;
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

    pub async fn get_validator_set_from_number(&mut self, block_number: u64) -> Vec<Info> {
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
        &mut self,
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
        let query_route = format!(
            "validators?height={}&per_page=100&page={}",
            block_number.to_string().as_str(),
            page_number.to_string().as_str()
        );

        let fetched_result = match &self.mode {
            InputDataMode::Rpc => {
                let res = self.request_from_rpc(&query_route, MAX_NUM_RETRIES).await;
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
    ) -> StepInputs<F> {
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
        let nb_validators = next_block_validators.len();
        assert!(
            nb_validators <= VALIDATOR_SET_SIZE_MAX,
            "The validator set size of the next block is larger than the
            VALIDATOR_SET_SIZE_MAX."
        );

        // Note: Extends the validator set with the absent validators.
        let next_block_validators = get_validator_data_from_block::<VALIDATOR_SET_SIZE_MAX, F>(
            &next_block_validators,
            &next_block_signed_header,
        );

        let encoded_chain_id = next_block_signed_header
            .header
            .chain_id
            .clone()
            .encode_vec();
        let next_block_chain_id_proof = self.get_merkle_proof(
            &next_block_signed_header.header,
            CHAIN_ID_INDEX as u64,
            encoded_chain_id.clone(),
        );
        // Extend the chain id to the maximum encoded length.
        let mut extended_chain_id = encoded_chain_id.clone();
        extended_chain_id.resize(PROTOBUF_CHAIN_ID_SIZE_BYTES, 0u8);
        let next_block_chain_id_proof = ChainIdProofValueType::<F> {
            chain_id: extended_chain_id,
            enc_chain_id_byte_length: encoded_chain_id.len() as u32,
            proof: next_block_chain_id_proof.1,
        };

        let next_block_height_proof = self.get_merkle_proof(
            &next_block_signed_header.header,
            BLOCK_HEIGHT_INDEX as u64,
            next_block_signed_header.header.height.encode_vec(),
        );
        let next_block_height_proof = HeightProofValueType::<F> {
            height: next_block_signed_header.header.height.value(),
            enc_height_byte_length: next_block_signed_header.header.height.encode_vec().len()
                as u32,
            proof: next_block_height_proof.1,
        };

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
        let round = next_block_signed_header.commit.round.value() as usize;
        let next_block_header = next_block_signed_header.header.hash();
        StepInputs {
            next_header: next_block_header.as_bytes().try_into().unwrap(),
            round,
            next_block_validators,
            nb_validators,
            next_block_chain_id_proof,
            next_block_height_proof,
            next_block_validators_hash_proof,
            next_block_last_block_id_proof,
            prev_block_next_validators_hash_proof,
        }
    }

    pub async fn get_skip_inputs<const VALIDATOR_SET_SIZE_MAX: usize, F: RichField>(
        &mut self,
        trusted_block_number: u64,
        trusted_block_hash: H256,
        target_block_number: u64,
    ) -> SkipInputs<F> {
        let trusted_block_validator_set = self
            .get_validator_set_from_number(trusted_block_number)
            .await;
        let nb_trusted_validators = trusted_block_validator_set.len();
        let target_block_validator_set = self
            .get_validator_set_from_number(target_block_number)
            .await;
        let nb_target_validators = target_block_validator_set.len();
        assert!(
            nb_trusted_validators <= VALIDATOR_SET_SIZE_MAX
                && nb_target_validators <= VALIDATOR_SET_SIZE_MAX,
            "The validator set size of the trusted or target block is larger than the 
            VALIDATOR_SET_SIZE_MAX."
        );

        let trusted_signed_header = self
            .get_signed_header_from_number(trusted_block_number)
            .await;
        let computed_trusted_header_hash = trusted_signed_header.header.hash();
        assert_eq!(
            computed_trusted_header_hash.as_bytes(),
            trusted_block_hash.as_bytes(),
            "Trusted header hash doesn't pass sanity check! An incorrect header was likely pushed 
            to the contract, typically the genesis header."
        );
        let target_signed_header = self
            .get_signed_header_from_number(target_block_number)
            .await;
        let target_block_header = target_signed_header.header.hash();
        let round = target_signed_header.commit.round.value() as usize;

        let target_block_validators = get_validator_data_from_block::<VALIDATOR_SET_SIZE_MAX, F>(
            &target_block_validator_set,
            &target_signed_header,
        );

        let encoded_chain_id = target_signed_header.header.chain_id.clone().encode_vec();
        let target_block_chain_id_proof = self.get_merkle_proof(
            &target_signed_header.header,
            CHAIN_ID_INDEX as u64,
            encoded_chain_id.clone(),
        );
        // Extend the chain id to the maximum encoded length.
        let mut extended_chain_id = encoded_chain_id.clone();
        extended_chain_id.resize(PROTOBUF_CHAIN_ID_SIZE_BYTES, 0u8);
        let target_block_chain_id_proof = ChainIdProofValueType::<F> {
            chain_id: extended_chain_id,
            enc_chain_id_byte_length: encoded_chain_id.len() as u32,
            proof: target_block_chain_id_proof.1,
        };

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

        let trusted_block_validators_hash_fields =
            validator_hash_field_from_block::<VALIDATOR_SET_SIZE_MAX, F>(
                &trusted_block_validator_set,
                &trusted_signed_header.commit,
            );
        let trusted_block_validators_hash_proof = self.get_inclusion_proof(
            &trusted_signed_header.header,
            VALIDATORS_HASH_INDEX as u64,
            trusted_signed_header.header.validators_hash.encode_vec(),
        );

        SkipInputs {
            target_block_validators,
            nb_target_validators,
            target_header: target_block_header.as_bytes().try_into().unwrap(),
            round,
            target_block_chain_id_proof,
            target_block_height_proof,
            target_block_validators_hash_proof,
            trusted_header: trusted_block_hash.as_bytes().try_into().unwrap(),
            trusted_block_validators_hash_proof,
            trusted_block_validators_hash_fields,
            nb_trusted_validators,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use plonky2x::prelude::GoldilocksField;
    use subtle_encoding::hex;

    use crate::consts::VALIDATOR_SET_SIZE_MAX;
    use crate::input::conversion::get_validator_data_from_block;

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

    type F = GoldilocksField;

    #[tokio::test]
    #[cfg_attr(feature = "ci", ignore)]
    async fn test_get_signed_vote() {
        let mut data_fetcher = super::InputDataFetcher {
            mode: super::InputDataMode::Rpc,
            ..Default::default()
        };

        let target_block_number = 600000;
        let target_block_validator_set = data_fetcher
            .get_validator_set_from_number(target_block_number)
            .await;
        let target_signed_header = data_fetcher
            .get_signed_header_from_number(target_block_number)
            .await;

        let _ = get_validator_data_from_block::<VALIDATOR_SET_SIZE_MAX, F>(
            &target_block_validator_set,
            &target_signed_header,
        );
    }

    #[tokio::test]
    #[cfg_attr(feature = "ci", ignore)]
    async fn test_find_header_with_nonzero_round() {
        let data_fetcher = super::InputDataFetcher {
            mode: super::InputDataMode::Rpc,
            ..Default::default()
        };

        let mut target_block_number = 610000;
        loop {
            println!("Checking block number: {}", target_block_number);
            let target_signed_header = data_fetcher
                .get_signed_header_from_number(target_block_number)
                .await;
            if target_signed_header.commit.round.value() != 0 {
                println!("Found header with non-zero round: {}", target_block_number);
                break;
            }
            target_block_number += 1;
        }
    }
}
