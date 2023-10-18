# Tendermint X
Implementation of zero-knowledge proof circuits for [Tendermint](https://tendermint.com/).

## Overview
Tendermint X's core contract is `TendermintX`, which stores the headers of Tendermint blocks. Users can query a `TendermintX` contract for the header of a specific block height, or for the latest header.

There are two entrypoints to a `TendermintX` contract, `step` and `skip`.

### skip (wip)
`skip` is used to jump from the current header to a non-consecutive header. 

For example, let's say block N has already been proven in the light client, and we want to prove block N+10. If validators from block N represent more than 1/3 of the voting power in block N+10, then we can skip from block N to block N+10, as long as 1) the validators from the trusted block have signed the new block, and 2) the new block is valid.

The methodology for doing so is described in the section 2.3 of [A Tendermint Light Client](https://arxiv.org/pdf/2010.07031.pdf).

### step (wip)
`step` is used to sequentially verify the next header after the current header.

This is rarely used, as `step` will only be invoked when the validator set changes by more than 2/3 in a single block.

## Deployment
The circuits are currently available on Succinct X [here](https://alpha.succinct.xyz/succinctlabs/zkqgb/releases).

There are currently TendermintX light clients tracking the following networks on Goerli:
- [Celestia Mocha-4 Testnet](https://goerli.etherscan.io/address/0x67ea962864cdad3f2202118dc6f65ff510f7bb4d)
