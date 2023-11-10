# Tendermint X
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
The circuits are currently available on Succinct X [here](https://platform.succinct.xyz/succinctlabs/tendermintx).

There are currently TendermintX light clients tracking the following networks on Goerli:
- [Celestia Mainnet](https://goerli.etherscan.io/address/0x0E9187150C3eEFcBce4E2a15aEC0136f45f4d6B2)

## Integrate
Deploy a `TendermintX` contract.
```
forge create --rpc-url $RPC_URL --private-key $PRIVATE_KEY --constructor-args 0x6e4f1e9ea315ebfd69d18c2db974eef6105fb803 --etherscan-api-key $ETHERSCAN_API_KEY --verify TendermintX
```

Initialize the `TendermintX` contract with genesis parameters.
```
forge script script/Genesis.s.sol --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast
```

Update the function ID's on the `TendermintX` contract.
```
forge script script/FunctionId.s.sol --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast
```


Run `TendermintX` script to update the light client continuously. 

Note: Update .env with the necessary variables before running.
```
cargo run --bin tendermintx --release
```
