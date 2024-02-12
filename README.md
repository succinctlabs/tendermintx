# Tendermint X

![Tendermint X](https://pbs.twimg.com/media/GBqB__WbsAAjjTF?format=jpg&name=4096x4096)

Implementation of zero-knowledge proof circuits for [Tendermint](https://tendermint.com/).

## Overview

Tendermint X's core contract is `TendermintX`, which stores the headers of Tendermint blocks. Users can query a `TendermintX` contract for the header of a specific block height, or for the latest header.

There are two entrypoints to a `TendermintX` contract, `step` and `skip`.

### skip

`skip` is used to jump from the current header to a non-consecutive header.

For example, let's say block N has already been proven in the light client, and we want to prove block N+10. If validators from block N represent more than 1/3 of the voting power in block N+10, then we can skip from block N to block N+10, as long as 1) the validators from the trusted block have signed the new block, and 2) the new block is valid.

The methodology for doing so is described in the section 2.3 of [A Tendermint Light Client](https://arxiv.org/pdf/2010.07031.pdf).

### step

`step` is used to sequentially verify the next header after the current header.

This is rarely used, as `step` will only be invoked when the validator set changes by more than 2/3 in a single block.

## Deployment

The circuits are currently available on Succinct X [here](https://alpha.succinct.xyz/succinctlabs/tendermintx).

There are currently Tendermint X light clients tracking the following networks on Goerli:

- [dYdX](https://goerli.etherscan.io/address/0x59eE2D9CFaC933c79Cc1D1d6767679636c0b539D#events)
- [Osmosis](https://goerli.etherscan.io/address/0xd4a723C4dd8a961ACcbC5a42f05862C63B32B701#events)
- [Celestia Mainnet](https://goerli.etherscan.io/address/0x0E9187150C3eEFcBce4E2a15aEC0136f45f4d6B2#events)

## Benchmarks

|  Chain   | # of Validators | plonky2 Proving Time | End to End Proving Time |
| :------: | :-------------: | :------------------: | :---------------------: |
|   dYdX   |       60        |        2 mins        |         5 mins          |
| Celestia |       100       |        5 mins        |         8 mins          |
| Osmosis  |       150       |        9 mins        |         12 mins         |

## Integrate Tendermint X

1. Request a Succinct Platform API Key: https://alpha.succinct.xyz/partner

2. Fork this repository: https://github.com/succinctlabs/tendermintx

3. Update the `VALIDATOR_SET_SIZE_MAX` to match that of your Tendermint chain in `circuits/consts.rs` (ex. 150 for Osmosis, 60 for dYdX). Push the changes to your fork.

4. Go to the [Succinct Platform](https://alpha.succinct.xyz).

5. Sign up for an account on the platform.

6. Create a new project on the Succinct Platform by importing your fork of `tendermintx`.

7. In your project on the platform, go to `Releases`. Create two new releases, one for `step` and one for `skip`. Use the `main` branch and set the entrypoint accordingly.

8. In your project on the platform, go to `Settings`. Set `TENDERMINT_RPC_URL` in `Environment Variables`. This should be a valid full node RPC for your Tendermint chain.

9. Once the releases are completed building, go to `Deployments` to deploy the verifiers for `step` and `skip`.

10. Open the code for your fork of `TendermintX` again.

11. Update `contracts/.env` accoridng to `contracts/.env.example`. Note: The genesis parameters are typically sourced from a recent header from your Tendermint chain.

12. Deploy your `TendermintX` contract and initialize it with your function ID & genesis parameters using the commands below.

```
forge install

forge script script/Deploy.s.sol --rpc-url $ETHEREUM_RPC_URL --private-key $PRIVATE_KEY --etherscan-api-key $ETHERSCAN_API_KEY --verify TendermintX --broadcast
```

13. Update `.env` according to `.env.example`.

14. Run `TendermintX` script to update the light client continuously (currently set to update once every 4 hours).

```
cargo run --bin tendermintx --release
```

14. Now, go the platform to monitor the status of your proofs. Generating a Tendermint LC proof takes anywhere from 4-15 minutes, depending on your validator set size.

## Misc

### Tendermint RPC's

To find a list of RPC's for most Tendermint chains, check out [this page](https://deving.zone/en/cosmos/chains) created by @deving_zone.

### Block Protocol Version

Tendermint X is configured to work with [CometBFT block protocol version 11](https://pkg.go.dev/github.com/ben2077/cometbft/version#pkg-constants). If this changes in the future, the Tendermint X circuits might need to be updated.
