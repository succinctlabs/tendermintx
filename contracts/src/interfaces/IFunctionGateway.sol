// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IFunctionGateway {
    function requestCallback(
        bytes32 _functionId,
        bytes memory _input,
        bytes memory _context,
        bytes4 _callbackSelector,
        uint32 _callbackGasLimit
    ) external payable returns (bytes32);

    function requestCall(
        bytes32 _functionId,
        bytes memory _input,
        address _address,
        bytes memory _data,
        uint32 _gasLimit
    ) external payable;

    function verifiedCall(
        bytes32 _functionId,
        bytes memory _input
    ) external view returns (bytes memory);

    function isCallback() external view returns (bool);
}
