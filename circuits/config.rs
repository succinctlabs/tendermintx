use std::fmt::Debug;

pub trait TendermintConfig<const CHAIN_ID_SIZE_BYTES: usize>:
    Debug + Clone + PartialEq + Sync + Send + 'static
{
    const CHAIN_ID_BYTES: &'static [u8];
}

/// Celestia's chain config.
pub const CELESTIA_CHAIN_ID_BYTES: &[u8] = b"celestia";
pub const CELESTIA_CHAIN_ID_SIZE_BYTES: usize = CELESTIA_CHAIN_ID_BYTES.len();
#[derive(Debug, Clone, PartialEq)]
pub struct CelestiaConfig;
impl TendermintConfig<CELESTIA_CHAIN_ID_SIZE_BYTES> for CelestiaConfig {
    const CHAIN_ID_BYTES: &'static [u8] = CELESTIA_CHAIN_ID_BYTES;
}

/// Mocha-4's chain config.
pub const MOCHA_4_CHAIN_ID_BYTES: &[u8] = b"mocha-4";
pub const MOCHA_4_CHAIN_ID_SIZE_BYTES: usize = MOCHA_4_CHAIN_ID_BYTES.len();
#[derive(Debug, Clone, PartialEq)]
pub struct Mocha4Config;
impl TendermintConfig<MOCHA_4_CHAIN_ID_SIZE_BYTES> for Mocha4Config {
    const CHAIN_ID_BYTES: &'static [u8] = MOCHA_4_CHAIN_ID_BYTES;
}
