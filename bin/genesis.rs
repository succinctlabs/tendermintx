use std::env;

use clap::Parser;
use log::info;
use tendermintx::input::InputDataFetcher;

#[derive(Parser, Debug, Clone)]
#[command(about = "Get the genesis parameters from a block.")]
pub struct GenesisArgs {
    #[arg(long, default_value = "1")]
    pub block: u64,
}

#[tokio::main]
pub async fn main() {
    env::set_var("RUST_LOG", "info");
    dotenv::dotenv().ok();
    env_logger::init();
    let data_fetcher = InputDataFetcher::default();
    let args = GenesisArgs::parse();

    let genesis_block = args.block;

    let signed_header = data_fetcher
        .get_signed_header_from_number(genesis_block)
        .await;
    let header_hash = signed_header.header.hash();
    info!(
        "Block {}'s header hash: {:?}",
        genesis_block,
        header_hash.to_string()
    );
}
