// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/TendermintX.sol";

contract TendermintXTest is Test {
    TendermintX public lightClient;

    function setUp() public {
        lightClient = new TendermintX(address(0));
    }

    function testGetEncodePackedStep() public view {
        // http://64.227.18.169:26657/block?height=10000
        uint64 height = 10000;
        bytes32 header = hex"A0123D5E4B8B8888A61F931EE2252D83568B97C223E0ECA9795B29B8BD8CBA2D";
        bytes memory encodedInput = abi.encodePacked(height, header);
        console.logBytes(encodedInput);
    }

    function testGetEncodePackedSkip() public view {
        // http://64.227.18.169:26657/block?height=10000
        uint64 height = 10000;
        bytes32 header = hex"A0123D5E4B8B8888A61F931EE2252D83568B97C223E0ECA9795B29B8BD8CBA2D";
        uint64 requestedHeight = 10004;
        bytes memory encodedInput = abi.encodePacked(
            height,
            header,
            requestedHeight
        );
        console.logBytes(encodedInput);
    }
}
