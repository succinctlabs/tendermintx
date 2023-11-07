//! To build the binary:
//!
//!     `cargo build --release --bin tendermintx`
//!

use std::env;

use alloy_sol_types::{sol, SolType};
use ethers::contract::abigen;
use ethers::core::types::Address;
use ethers::providers::{Http, Provider};
use ethers::types::{Bytes, H256};
use log::{error, info};
use subtle_encoding::hex;
use tendermintx::input::InputDataFetcher;

// Note: Update ABI when updating contract.
abigen!(TendermintX, "./abi/TendermintX.abi.json");

struct TendermintXConfig {
    address: Address,
    chain_id: u32,
    step_function_id: H256,
    skip_function_id: H256,
}

struct TendermintXOperator {
    config: TendermintXConfig,
    contract: TendermintX<Provider<Http>>,
    data_fetcher: InputDataFetcher,
}

#[allow(non_snake_case)]
#[derive(serde::Serialize, serde::Deserialize)]
struct OffchainInput {
    chainId: u32,
    to: String,
    data: String,
    functionId: String,
    input: String,
}

type StepCalldataTuple = sol! { tuple(uint64,) };
type StepInputTuple = sol! { tuple(uint64, bytes32) };

type SkipCalldataTuple = sol! { tuple(uint64, uint64) };
type SkipInputTuple = sol! { tuple(uint64, bytes32, uint64) };

impl TendermintXOperator {
    pub fn new() -> Self {
        dotenv::dotenv().ok();

        let config = Self::get_config();

        let ethereum_rpc_url = env::var("RPC_URL").expect("RPC_URL must be set");
        let provider =
            Provider::<Http>::try_from(ethereum_rpc_url).expect("could not connect to client");

        let contract = TendermintX::new(config.address, provider.into());

        let tendermint_rpc_url =
            env::var("TENDERMINT_RPC_URL").expect("TENDERMINT_RPC_URL must be set");
        let data_fetcher = InputDataFetcher::new(&tendermint_rpc_url, "");

        Self {
            config,
            contract,
            data_fetcher,
        }
    }

    fn get_config() -> TendermintXConfig {
        let contract_address = env::var("CONTRACT_ADDRESS").expect("CONTRACT_ADDRESS must be set");
        let chain_id = env::var("CHAIN_ID").expect("CHAIN_ID must be set");
        // TODO: TendermintX on Goerli: https://goerli.etherscan.io/address/#code
        let address = contract_address
            .parse::<Address>()
            .expect("invalid address");

        // Load the function IDs.
        let step_id_env = env::var("STEP_FUNCTION_ID").expect("STEP_FUNCTION_ID must be set");
        let step_function_id = H256::from_slice(
            &hex::decode(step_id_env.strip_prefix("0x").unwrap_or(&step_id_env))
                .expect("invalid hex for step_function_id, expected 0x prefix"),
        );
        let skip_id_env = env::var("SKIP_FUNCTION_ID").expect("SKIP_FUNCTION_ID must be set");
        let skip_function_id = H256::from_slice(
            &hex::decode(skip_id_env.strip_prefix("0x").unwrap_or(&skip_id_env))
                .expect("invalid hex for skip_function_id, expected 0x prefix"),
        );

        TendermintXConfig {
            address,
            chain_id: chain_id.parse::<u32>().expect("invalid chain id"),
            step_function_id,
            skip_function_id,
        }
    }

    async fn submit_request(&self, function_data: Vec<u8>, input: Vec<u8>, function_id: H256) {
        // All data except for chainId is a string, and needs a 0x prefix.
        let data = OffchainInput {
            chainId: self.config.chain_id,
            to: Bytes::from(self.config.address.0).to_string(),
            data: Bytes::from(function_data).to_string(),
            functionId: Bytes::from(function_id.0).to_string(),
            input: Bytes::from(input).to_string(),
        };

        // Stringify the data into JSON format.
        let serialized_data = serde_json::to_string(&data).unwrap();

        // TODO: Update with config.
        let request_url = "https://alpha.succinct.xyz/api/request/new";

        // Submit POST request to the offchain worker.
        let client = reqwest::Client::new();
        let res = client
            .post(request_url)
            .header("Content-Type", "application/json")
            .body(serialized_data)
            .send()
            .await
            .expect("Failed to send request.");

        if res.status().is_success() {
            info!("Successfully submitted request.");
        } else {
            // TODO: Log more specific error message.
            error!("Failed to submit request.");
        }
    }

    async fn request_step(&self, trusted_block: u64) {
        let trusted_header_hash = self
            .contract
            .block_height_to_header_hash(trusted_block)
            .await
            .unwrap();

        let input = StepInputTuple::abi_encode_packed(&(trusted_block, trusted_header_hash));

        let function_signature = "step(uint64)";
        let function_selector = ethers::utils::id(function_signature).to_vec();
        let encoded_parameters = StepCalldataTuple::abi_encode_sequence(&(trusted_block,));
        // Concat function selector and encoded parameters.
        let function_data = [&function_selector[..], &encoded_parameters[..]].concat();

        self.submit_request(function_data, input, self.config.step_function_id)
            .await;
    }

    async fn request_skip(&self, trusted_block: u64, target_block: u64) {
        let trusted_header_hash = self
            .contract
            .block_height_to_header_hash(trusted_block)
            .await
            .unwrap();

        let input =
            SkipInputTuple::abi_encode_packed(&(trusted_block, trusted_header_hash, target_block));

        let function_signature = "skip(uint64,uint64)";
        let function_selector = ethers::utils::id(function_signature).to_vec();
        let encoded_parameters =
            SkipCalldataTuple::abi_encode_sequence(&(trusted_block, target_block));
        // Concat function selector and encoded parameters.
        let function_data = [&function_selector[..], &encoded_parameters[..]].concat();

        self.submit_request(function_data, input, self.config.skip_function_id)
            .await;
    }

    async fn run(&self) {
        // Loop every 30 minutes.
        const LOOP_DELAY: u64 = 30;

        // The upper limit of the largest skip that can be requested. This is bounded by the unbonding
        // period, which for most Tendermint chains is ~2 weeks, or ~100K blocks. This is set to 10K to
        // be safe, which is ~1 day.
        let skip_max = 10000;
        loop {
            let current_block = self.contract.latest_block().await.unwrap();

            // Get the head of the chain.
            let latest_header = self.data_fetcher.get_latest_header().await;
            let latest_block = latest_header.height.value();

            // Subtract 2 blocks to account for the time it takes for a block to be processed by
            // consensus.
            let max_end_block = std::cmp::min(latest_block - 2, current_block + skip_max);

            let target_block = self
                .data_fetcher
                .find_block_to_request(current_block, max_end_block)
                .await;

            if target_block - current_block == 1 {
                // Request the step if the target block is the next block.
                self.request_step(current_block).await;
            } else {
                // Request a skip if the target block is not the next block.
                self.request_skip(current_block, target_block).await;
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(60 * LOOP_DELAY)).await;
        }
    }
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    env_logger::init();

    let operator = TendermintXOperator::new();
    operator.run().await;
}
