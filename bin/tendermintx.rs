//! To build the binary:
//!
//!     `cargo build --release --bin tendermintx`
//!

use std::env;

use alloy_primitives::{Address, Bytes, B256};
use alloy_sol_types::{sol, SolType};
use anyhow::Result;
use ethers::abi::AbiEncode;
use ethers::contract::abigen;
use ethers::providers::{Http, Provider};
use log::{error, info};
use subtle_encoding::hex;
use succinct_client::request::SuccinctClient;
use tendermintx::input::InputDataFetcher;

// Note: Update ABI when updating contract.
abigen!(TendermintX, "./abi/TendermintX.abi.json");

struct TendermintXConfig {
    address: Address,
    chain_id: u32,
    step_function_id: B256,
    skip_function_id: B256,
}

struct TendermintXOperator {
    config: TendermintXConfig,
    contract: TendermintX<Provider<Http>>,
    client: SuccinctClient,
    data_fetcher: InputDataFetcher,
}

type StepInputTuple = sol! { tuple(uint64, bytes32) };

type SkipInputTuple = sol! { tuple(uint64, bytes32, uint64) };

impl TendermintXOperator {
    pub fn new() -> Self {
        let config = Self::get_config();

        let ethereum_rpc_url = env::var("RPC_URL").expect("RPC_URL must be set");
        let provider =
            Provider::<Http>::try_from(ethereum_rpc_url).expect("could not connect to client");

        let contract = TendermintX::new(config.address.0 .0, provider.into());

        let tendermint_rpc_url =
            env::var("TENDERMINT_RPC_URL").expect("TENDERMINT_RPC_URL must be set");
        let data_fetcher = InputDataFetcher::new(&tendermint_rpc_url, "");

        let succinct_rpc_url = env::var("SUCCINCT_RPC_URL").expect("SUCCINCT_RPC_URL must be set");
        let succinct_api_key = env::var("SUCCINCT_API_KEY").expect("SUCCINCT_API_KEY must be set");
        let client = SuccinctClient::new(succinct_rpc_url, succinct_api_key);

        Self {
            config,
            contract,
            client,
            data_fetcher,
        }
    }

    fn get_config() -> TendermintXConfig {
        let contract_address = env::var("CONTRACT_ADDRESS").expect("CONTRACT_ADDRESS must be set");
        let chain_id = env::var("CHAIN_ID").expect("CHAIN_ID must be set");
        let address = contract_address
            .parse::<Address>()
            .expect("invalid address");

        // Load the function IDs.
        let step_id_env = env::var("STEP_FUNCTION_ID").expect("STEP_FUNCTION_ID must be set");
        let step_function_id = B256::from_slice(
            &hex::decode(step_id_env.strip_prefix("0x").unwrap_or(&step_id_env))
                .expect("invalid hex for step_function_id, expected 0x prefix"),
        );
        let skip_id_env = env::var("SKIP_FUNCTION_ID").expect("SKIP_FUNCTION_ID must be set");
        let skip_function_id = B256::from_slice(
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

    async fn request_step(&self, trusted_block: u64) -> Result<String> {
        let trusted_header_hash = self
            .contract
            .block_height_to_header_hash(trusted_block)
            .await
            .unwrap();

        let input = StepInputTuple::abi_encode_packed(&(trusted_block, trusted_header_hash));

        let step_call = StepCall { trusted_block };
        let function_data = step_call.encode();

        let request_id = self
            .client
            .submit_platform_request(
                self.config.chain_id,
                self.config.address,
                function_data.into(),
                self.config.step_function_id,
                Bytes::copy_from_slice(&input),
            )
            .await?;
        Ok(request_id)
    }

    async fn request_skip(&self, trusted_block: u64, target_block: u64) -> Result<String> {
        let trusted_header_hash = self
            .contract
            .block_height_to_header_hash(trusted_block)
            .await
            .unwrap();

        let input =
            SkipInputTuple::abi_encode_packed(&(trusted_block, trusted_header_hash, target_block));

        let skip_call = SkipCall {
            trusted_block,
            target_block,
        };
        let function_data = skip_call.encode();

        let request_id = self
            .client
            .submit_platform_request(
                self.config.chain_id,
                self.config.address,
                function_data.into(),
                self.config.skip_function_id,
                Bytes::copy_from_slice(&input),
            )
            .await?;
        Ok(request_id)
    }

    async fn run(&self) {
        // Loop every 240 minutes.
        const LOOP_DELAY: u64 = 240;

        // The upper limit of the largest skip that can be requested. This is bounded by the unbonding
        // period, which for most Tendermint chains is ~2 weeks, or ~100K blocks. This is set to 10K to
        // be safe, which is ~1 day.
        let skip_max = 10000;
        loop {
            let current_block = self.contract.latest_block().await.unwrap();

            // Get the head of the chain.
            let latest_signed_header = self.data_fetcher.get_latest_signed_header().await;
            let latest_block = latest_signed_header.header.height.value();

            // Get the maximum block height we can request.
            let max_end_block = std::cmp::min(latest_block, current_block + skip_max);

            let target_block = self
                .data_fetcher
                .find_block_to_request(current_block, max_end_block)
                .await;

            if target_block - current_block == 1 {
                // Request the step if the target block is the next block.
                match self.request_step(current_block).await {
                    Ok(request_id) => {
                        info!("Step request submitted: {}", request_id)
                    }
                    Err(e) => {
                        error!("Step request failed: {}", e);
                        continue;
                    }
                };
            } else {
                // Request a skip if the target block is not the next block.
                match self.request_skip(current_block, target_block).await {
                    Ok(request_id) => {
                        info!("Skip request submitted: {}", request_id)
                    }
                    Err(e) => {
                        error!("Skip request failed: {}", e);
                        continue;
                    }
                };
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(60 * LOOP_DELAY)).await;
        }
    }
}

#[tokio::main]
async fn main() {
    env::set_var("RUST_LOG", "info");
    dotenv::dotenv().ok();
    env_logger::init();

    let operator = TendermintXOperator::new();
    operator.run().await;
}
