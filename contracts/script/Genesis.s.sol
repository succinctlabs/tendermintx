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
        TendermintX lightClient = TendermintX(
            0xd4a723C4dd8a961ACcbC5a42f05862C63B32B701
        );

        uint64 height = 12320000;
        bytes32 header = hex"9928728c76ceacbdd6212bf3f05ee20686895d84f735d91ad042e4cf19ec440c";
        lightClient.setGenesisHeader(height, header);
    }
}
