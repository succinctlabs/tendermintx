// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import {TendermintX} from "../src/TendermintX.sol";

// forge script script/TendermintX.s.sol --verifier etherscan --private-key
// forge verify-contract <address> TendermintX --chain 5 --etherscan-api-key ${ETHERSCAN_API_KEY} --constructor-args "0x000000000000000000000000852a94f8309d445d27222edb1e92a4e83dddd2a8"
contract GenesisScript is Script {
    function setUp() public {}

    function run() public {
        vm.startBroadcast();
        // Use the below to interact with an already deployed ZK light client.
        address lightClientAddress = vm.envAddress("CONTRACT_ADDRESS");
        TendermintX lightClient = TendermintX(lightClientAddress);

        uint64 height = 1;
        bytes32 header = hex"6be39efd10ba412a9db5288488303f5dd32cf386707a5bef33617f4c43301872";
        lightClient.setGenesisHeader(height, header);
    }
}
