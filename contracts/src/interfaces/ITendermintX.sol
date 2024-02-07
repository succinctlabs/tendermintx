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

    /// @notice Inputs of a freeze request.
    /// @param trustedBlock The trusted block for the freeze request (skip).
    /// @param trustedHeader The header hash of the trusted block.
    /// @param conflictBlock The block with a conflicting header for the freeze.
    event FreezeRequested(
        uint64 indexed trustedBlock,
        bytes32 indexed trustedHeader,
        uint64 indexed conflictBlock
    );

    /// @notice Emits an event if the contract is now frozen.
    /// @param conflictBlock The block that conflicts.
    /// @param existingHeader The existing header of the conflict block in the contract.
    /// @param conflictingHeader The new conflicting header provided in the proof.
    event Freeze(
        uint64 indexed conflictBlock,
        bytes32 existingHeader,
        bytes32 conflictingHeader
    );

    /// @notice Contract is now frozen.
    error ContractFrozen();

    /// @notice Invalid conflict block, the proved header is not in conflict.
    error InvalidConflictBlock();

    /// @notice Trusted header not found.
    error TrustedHeaderNotFound();

    /// @notice Latest header not found.
    error LatestHeaderNotFound();

    /// @notice Target block for proof must be greater than latest block and less than the
    /// latest block plus the maximum number of skipped blocks.
    error TargetBlockNotInRange();

    /// @notice The range of blocks in a request is greater than the maximum allowed.
    error ProofBlockRangeTooLarge();
}
