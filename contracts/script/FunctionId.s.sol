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

        address lightClientAddress = vm.envAddress("CONTRACT_ADDRESS");
        // Use the below to interact with an already deployed ZK light client.
        TendermintX lightClient = TendermintX(lightClientAddress);

        bytes32 stepFunctionId = vm.envBytes32("STEP_FUNCTION_ID");
        bytes32 skipFunctionId = vm.envBytes32("SKIP_FUNCTION_ID");

        lightClient.updateStepId(stepFunctionId);
        lightClient.updateSkipId(skipFunctionId);
    }
}
