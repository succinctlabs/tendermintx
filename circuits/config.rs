use std::fmt::Debug;

pub trait TendermintConfig<const CHAIN_ID_SIZE_BYTES: usize>:
    Debug + Clone + PartialEq + Sync + Send + 'static
{
    const CHAIN_ID_BYTES: &'static [u8];
}

/// The chain ID of the Tendermint chain.
pub const CHAIN_ID_BYTES: &[u8] = b"mocha-4";
pub const CHAIN_ID_SIZE_BYTES: usize = CHAIN_ID_BYTES.len();
#[derive(Debug, Clone, PartialEq)]
pub struct CelestiaConfig;
impl TendermintConfig<CHAIN_ID_SIZE_BYTES> for CelestiaConfig {
    const CHAIN_ID_BYTES: &'static [u8] = CHAIN_ID_BYTES;
}
