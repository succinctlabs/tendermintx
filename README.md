# Tendermint X

![Tendermint X](https://pbs.twimg.com/media/GBqB__WbsAAjjTF?format=jpg&name=4096x4096)

Implementation of zero-knowledge proof circuits for [Tendermint](https://tendermint.com/).

## Overview

Tendermint X's core contract is `TendermintX`, which stores the headers of Tendermint blocks. Users can query a `TendermintX` contract for the header of a specific block height, or for the latest header.

There are two entrypoints to a `TendermintX` contract, `step` and `skip`.

### skip

`skip` is used to jump from the current header to a non-consecutive header.

For example, let's say block N has already been proven in the light client, and we want to prove block N+10. We can skip from block N to block N+10 if 1) the validators who have signed the commit for block N+10 comprise > 1/3 of the voting power on block N and 2) validators comprimising > 2/3 of the voting power on block N+10 have signed the commit for block N+10.

The methodology for doing so is described in the section 6 of [A Tendermint Light Client](https://arxiv.org/pdf/2010.07031.pdf).

### step

`step` is used to sequentially verify the next header after the current header.

This is rarely used, as `step` will only be invoked when the validator set changes by more than 2/3 in a single block.

## Deploy Tendermint X for a chain

### Tendermint X Circuits

1. Fork this repository: https://github.com/succinctlabs/tendermintx

2. Update the `VALIDATOR_SET_SIZE_MAX` to match that of your Tendermint chain in `circuits/consts.rs`. Push the changes to your fork.

3. Add a new circuit config for your Tendermint chain in `circuits/config.rs`. Replace `celestia` with the chain ID (network name) of your Tendermint chain.
    ```rust
    /// Example chain config for Celestia
    pub const CELESTIA_CHAIN_ID_BYTES: &[u8] = b"celestia";
    pub const CELESTIA_CHAIN_ID_SIZE_BYTES: usize = CELESTIA_CHAIN_ID_BYTES.len();
    #[derive(Debug, Clone, PartialEq)]
    pub struct CelestiaConfig;
    impl TendermintConfig<CELESTIA_CHAIN_ID_SIZE_BYTES> for CelestiaConfig {
        const CHAIN_ID_BYTES: &'static [u8] = CELESTIA_CHAIN_ID_BYTES;
        const SKIP_MAX: usize = SKIP_MAX;
    }   
    ```

4. Update `bin/skip.rs` and `bin/step.rs` to use your new chain config instead of `CelestiaConfig`.

### Set up circuits on the Succinct Platform


1. Go to the [Succinct Platform](https://alpha.succinct.xyz).

2. Sign up for an account on the platform.

3. Create a new project on the Succinct Platform by importing your fork of `tendermintx`.

4. In your project on the platform, go to `Releases`. Create two new releases, one for `step` and one for `skip`. Use the `main` branch and set the entrypoint accordingly.

5. In your project on the platform, go to `Settings`. Set `TENDERMINT_RPC_URL` in `Environment Variables`. This should be a valid full node RPC for your Tendermint chain.

6. Once the releases are completed building, go to `Deployments` to deploy the verifiers for `step` and `skip`.

### Deploy Tendermint X Contracts
1. Open the code for your fork of `tendermintx` again.

2. Update `contracts/.env` accoridng to `contracts/.env.example`. Note: The genesis parameters are typically sourced from a recent header from your Tendermint chain.

3. Deploy your `TendermintX` contract and initialize it with your function ID & genesis parameters using the commands below.

```
forge install

forge script script/Deploy.s.sol --rpc-url $ETHEREUM_RPC_URL --private-key $PRIVATE_KEY --etherscan-api-key $ETHERSCAN_API_KEY --verify TendermintX --broadcast
```

### Run the light client operator

1. Update `.env` according to `.env.example`.
    1. Get `SUCCINCT_API_KEY` from your Succinct Platform user/project settings.
    2. `SUCCINCT_RPC_URL`=`https://alpha.succinct.xyz/api`

2. Run `TendermintX` script to update the light client continuously (currently set to update once every 4 hours).

```
cargo run --bin tendermintx --release
```

3. Now, go the platform to monitor the status of your proofs. Generating a Tendermint LC proof takes anywhere from 4-10 minutes, depending on your validator set size.

## Misc

### Tendermint RPC's

To find a list of RPC's for most Tendermint chains, check out [this page](https://deving.zone/en/cosmos/chains) created by @deving_zone.

### Block Protocol Version

Tendermint X is configured to work with [CometBFT block protocol version 11](https://pkg.go.dev/github.com/ben2077/cometbft/version#pkg-constants). If this changes in the future, the Tendermint X circuits might need to be updated.

## Audit

### Informal Audit

- Tendermint X has been audited by Informal Systems. The audit report can be found [here](audits/informal/audit.pdf).
