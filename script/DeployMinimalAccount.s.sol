// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import {MinimalAccount} from "../src/ethereum/MinimalAccount.sol";
import {HelperConfig} from "./HelperConfig.s.sol";

// This script will house the core logic required to deploy our MinimalAccount smart contract to the blockchain.

contract DeployMinimal is Script {
    function run() public returns (HelperConfig, MinimalAccount) {
        return deployMinimalAccount();
    }

    function deployMinimalAccount() public returns (HelperConfig, MinimalAccount) {
        HelperConfig helperConfig = new HelperConfig();
        HelperConfig.NetworkConfig memory config = helperConfig.getConfig();

        // The MinimalAccount constructor (if Ownable) might set config.account as owner if it's the broadcaster.
        // This explicit transfer ensures the script runner (msg.sender in script context) becomes the owner,
        // or reaffirms ownership if config.account == msg.sender.
        // It's often good practice for clarity and to ensure the intended final owner.

        vm.startBroadcast(config.account); // Use the burner wallet from config for broadcasting
        MinimalAccount minimalAccount = new MinimalAccount(config.entryPoint);
        minimalAccount.transferOwnership(config.account);
        vm.stopBroadcast();
        return (helperConfig, minimalAccount);
    }
}
