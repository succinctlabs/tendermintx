// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import {TendermintX} from "../src/TendermintX.sol";

// forge script script/TendermintX.s.sol --verifier etherscan --private-key
// forge verify-contract <address> TendermintX --chain 5 --etherscan-api-key ${ETHERSCAN_API_KEY} --constructor-args "0x000000000000000000000000852a94f8309d445d27222edb1e92a4e83dddd2a8"
contract FunctionIdScript is Script {
    function setUp() public {}

    function run() public {
        vm.startBroadcast();
        // Use the below to interact with an already deployed ZK light client.
        TendermintX lightClient = TendermintX(
            0x0E9187150C3eEFcBce4E2a15aEC0136f45f4d6B2
        );

        bytes32 stepFunctionId = hex"2569c8472d303fedd0ef9243c3ed0187d8ec34f03cff595c811296b8fbd1fc79";
        bytes32 skipFunctionId = hex"d01199248505b4bdfea473b746c9d0c42556dd56a671e1d0c5b9555a9eed41f5";

        lightClient.updateStepId(stepFunctionId);
        lightClient.updateSkipId(skipFunctionId);
    }
}
