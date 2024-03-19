// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {ISuccinctGateway} from "./interfaces/ISuccinctGateway.sol";
import {ITendermintX} from "./interfaces/ITendermintX.sol";

/// @notice The TendermintX contract is a light client for Tendermint.
/// @dev The light client can not go out of sync for the trusting period (2 weeks).
contract TendermintX is ITendermintX {
    /// @notice The maximum number of blocks that can be skipped. This is typically the length of
    /// trusting period. Below, this is set to 2 weeks, which is roughly 100800 blocks if the
    /// block time is 12 seconds.
    uint64 public constant SKIP_MAX = 100800;

    /// @notice The address of the gateway contract.
    address public gateway;

    /// @notice The latest block that has been committed.
    uint64 public latestBlock;

    /// @notice Maps block heights to their header hashes.
    mapping(uint64 => bytes32) public blockHeightToHeaderHash;

    /// @notice Skip function id.
    bytes32 public skipFunctionId;

    /// @notice Step function id.
    bytes32 public stepFunctionId;

    /// @notice Initialize the contract with the address of the gateway contract.
    constructor(address _gateway) {
        gateway = _gateway;
    }

    /// @notice Update the address of the gateway contract.
    function updateGateway(address _gateway) external {
        gateway = _gateway;
    }

    /// @notice Update the function ID for header range.
    function updateSkipId(bytes32 _functionId) external {
        skipFunctionId = _functionId;
    }

    /// @notice Update the function ID for next header.
    function updateStepId(bytes32 _functionId) external {
        stepFunctionId = _functionId;
    }

    /// Note: Only for testnet. The genesis header should be set when initializing the contract.
    function setGenesisHeader(uint64 _height, bytes32 _header) external {
        blockHeightToHeaderHash[_height] = _header;
        latestBlock = _height;
    }

    /// @notice Prove the validity of the header at the target block.
    /// @param _targetBlock The block to skip to.
    /// @dev Skip proof is valid if more than 1/3 of the voting power signed on _targetBlock is from validators in the validator set for latestBlock.
    /// Request will fail if the target block is more than SKIP_MAX blocks ahead of the latest block.
    /// Pass both the latest block and the target block as context, as the latest block may change before the request is fulfilled.
    function requestSkip(uint64 _targetBlock) external payable {
        bytes32 latestHeader = blockHeightToHeaderHash[latestBlock];
        if (latestHeader == bytes32(0)) {
            revert LatestHeaderNotFound();
        }

        if (
            _targetBlock <= latestBlock || _targetBlock > latestBlock + SKIP_MAX
        ) {
            revert TargetBlockNotInRange();
        }

        ISuccinctGateway(gateway).requestCall{value: msg.value}(
            skipFunctionId,
            abi.encodePacked(latestBlock, latestHeader, _targetBlock),
            address(this),
            abi.encodeWithSelector(
                this.skip.selector,
                latestBlock,
                _targetBlock
            ),
            500000
        );

        emit SkipRequested(latestBlock, latestHeader, _targetBlock);
    }

    /// @notice Stores the new header for targetBlock.
    /// @param _trustedBlock The latest block when the request was made.
    /// @param _targetBlock The block to skip to.
    function skip(uint64 _trustedBlock, uint64 _targetBlock) external {
        bytes32 trustedHeader = blockHeightToHeaderHash[_trustedBlock];
        if (trustedHeader == bytes32(0)) {
            revert TrustedHeaderNotFound();
        }

        if (
            _targetBlock <= latestBlock || _targetBlock > latestBlock + SKIP_MAX
        ) {
            revert TargetBlockNotInRange();
        }

        // Encode the circuit input.
        bytes memory input = abi.encodePacked(
            _trustedBlock,
            trustedHeader,
            _targetBlock
        );

        // Call gateway to get the proof result.
        bytes memory requestResult = ISuccinctGateway(gateway).verifiedCall(
            skipFunctionId,
            input
        );

        // Read the target header from request result.
        bytes32 targetHeader = abi.decode(requestResult, (bytes32));

        blockHeightToHeaderHash[_targetBlock] = targetHeader;
        latestBlock = _targetBlock;

        emit HeadUpdate(_targetBlock, targetHeader);
    }

    /// @notice Prove the validity of the header at latestBlock + 1.
    /// @dev Only used if 2/3 of voting power in a validator set changes in one block.
    function requestStep() external payable {
        bytes32 latestHeader = blockHeightToHeaderHash[latestBlock];
        if (latestHeader == bytes32(0)) {
            revert LatestHeaderNotFound();
        }

        ISuccinctGateway(gateway).requestCall{value: msg.value}(
            stepFunctionId,
            abi.encodePacked(latestBlock, latestHeader),
            address(this),
            abi.encodeWithSelector(this.step.selector, latestBlock),
            500000
        );
        emit StepRequested(latestBlock, latestHeader);
    }

    /// @notice Stores the new header for _trustedBlock + 1.
    /// @param _trustedBlock The latest block when the request was made.
    function step(uint64 _trustedBlock) external {
        bytes32 trustedHeader = blockHeightToHeaderHash[_trustedBlock];
        if (trustedHeader == bytes32(0)) {
            revert TrustedHeaderNotFound();
        }

        uint64 nextBlock = _trustedBlock + 1;
        if (nextBlock <= latestBlock) {
            revert TargetBlockNotInRange();
        }

        bytes memory input = abi.encodePacked(_trustedBlock, trustedHeader);

        // Call gateway to get the proof result.
        bytes memory requestResult = ISuccinctGateway(gateway).verifiedCall(
            stepFunctionId,
            input
        );

        // Read the new header from request result.
        bytes32 newHeader = abi.decode(requestResult, (bytes32));

        blockHeightToHeaderHash[nextBlock] = newHeader;
        latestBlock = nextBlock;

        emit HeadUpdate(nextBlock, newHeader);
    }

    /// @dev See "./ITendermintX.sol"
    function getHeaderHash(uint64 height) external view returns (bytes32) {
        return blockHeightToHeaderHash[height];
    }
}
