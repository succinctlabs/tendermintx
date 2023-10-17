// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface ITendermintX {
    /// @notice Emits event with the new head update.
    event HeadUpdate(uint64 blockNumber, bytes32 headerHash);

    /// @notice Inputs of a step request.
    /// @param trustedBlock The trusted block for the skip.
    /// @param trustedHeader The header hash of the trusted block.
    event StepRequested(
        uint64 indexed trustedBlock,
        bytes32 indexed trustedHeader
    );

    /// @notice Inputs of a skip request.
    /// @param trustedBlock The trusted block for the skip.
    /// @param trustedHeader The header hash of the trusted block.
    /// @param targetBlock The target block of the skip.
    event SkipRequested(
        uint64 indexed trustedBlock,
        bytes32 indexed trustedHeader,
        uint64 indexed targetBlock
    );

    /// @notice Latest header not found.
    error LatestHeaderNotFound();

    /// @notice Target block for proof must be greater than latest block.
    error TargetLessThanLatest();

    /// @notice The range of blocks in a request is greater than the maximum allowed.
    error ProofBlockRangeTooLarge();

    /// @notice Gets the header hash of a block.
    /// @param blockNumber The block number to get the header hash of.
    function getHeaderHash(uint64 blockNumber) external view returns (bytes32);

    /// @notice Gets the latest block number updated by the light client.
    function latestBlock() external view returns (uint64);
}
