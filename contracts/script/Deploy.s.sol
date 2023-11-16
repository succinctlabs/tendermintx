// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import {TendermintX} from "../src/TendermintX.sol";

contract DeployScript is Script {
    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        address gateway = 0x6e4f1e9eA315EBFd69d18C2DB974EEf6105FB803;
        // Use the below to interact with an already deployed ZK light client.
        TendermintX lightClient = new TendermintX(gateway);

        bytes32 stepFunctionId = vm.envBytes32("STEP_FUNCTION_ID");
        bytes32 skipFunctionId = vm.envBytes32("SKIP_FUNCTION_ID");

        lightClient.updateStepId(stepFunctionId);
        lightClient.updateSkipId(skipFunctionId);

        uint64 height = uint64(vm.envUint("GENESIS_HEIGHT"));
        bytes32 header = vm.envBytes32("GENESIS_HEADER");
        lightClient.setGenesisHeader(height, header);
    }
}
