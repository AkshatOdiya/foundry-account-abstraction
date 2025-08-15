// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";
import {PackedUserOperation} from "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {HelperConfig} from "./HelperConfig.s.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/**
 * @notice SendPackedUserOp.s.sol
 * Will serve as the central hub for interacting with the account abstraction system.
 * It will be responsible for constructing, signing, and dispatching PackedUserOperations
 */
contract SendPackedUserOp is Script {
    using MessageHashUtils for bytes32;

    function run() public {}

    function generatedSignedUserOperation(
        bytes memory callData,
        HelperConfig.NetworkConfig memory config,
        address minimalAccount
    ) public view returns (PackedUserOperation memory) {
        // 1. Generate Unsigned Data

        // Fetch the nonce for the sender (smart account address) from the EntryPoint
        // For simplicity, assume the 'config.account' is the smart account for now,
        // though in reality, this would be the smart account address, and config.account the EOA owner.
        // Nonce would be: IEntryPoint(config.entryPoint).getNonce(config.account, nonceKey);
        // For Now, use a placeholder nonce or assume it's passed in.

        // the EntryPoint typically expects the first nonce to be 0. The vm.getNonce() cheatcode might return 1 if it's
        // tracking nonces similarly to EOAs or based on other contract creations/interactions in the test environment for an account that has not yet had a UserOperation processed
        uint256 nonce = vm.getNonce(minimalAccount) - 1;
        PackedUserOperation memory userOp = _generateUnsignedUserOperation(callData, minimalAccount, nonce);

        // 2. getUserOp hash
        // We need to cast the config.entryPoint address to the IEntryPoint interface
        bytes32 userOpHash = IEntryPoint(config.entryPoint).getUserOpHash(userOp);

        // Prepare the hash for EIP-191 signing (standard Ethereum signed message)
        // This prepends "\x19Ethereum Signed Message:\n32" and re-hashes.
        bytes32 digest = userOpHash.toEthSignedMessageHash();

        // 3. Sign it
        // 'config.account' here is the EOA that owns/controls the smart account.
        // This EOA must be unlocked for vm.sign to work without a private key.
        uint8 v;
        bytes32 r;
        bytes32 s;
        uint256 ANVIL_DEFAULT_PRIVATE_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
        if (block.chainid == 31337) {
            (v, r, s) = vm.sign(ANVIL_DEFAULT_PRIVATE_KEY, digest);
        } else {
            (v, r, s) = vm.sign(vm.envUint("SEPOLIA_PRIVATE_KEY"), digest);
        }

        // Construct the final signature.
        // IMPORTANT: The order is R, S, V (abi.encodePacked(r, s, v)).
        // This differs from vm.sign's return order (v, r, s).
        userOp.signature = abi.encodePacked(r, s, v); //Note the order
        return userOp;
    }

    function _generateUnsignedUserOperation(bytes memory callData, address sender, uint256 nonce)
        internal
        pure
        returns (PackedUserOperation memory)
    {
        // Dont worry too much about these gasfee/gaslimits
        uint128 verificationGasLimit = 16777216;
        uint128 callGasLimit = verificationGasLimit;
        uint128 maxPriorityFeePerGas = 256;
        uint128 maxFeePerGas = maxPriorityFeePerGas;
        return PackedUserOperation({
            sender: sender, // The EntryPoint expects sender to be the smart contract account that will validate the UserOperation.
            nonce: nonce,
            initCode: hex"",
            callData: callData,
            accountGasLimits: bytes32(uint256(verificationGasLimit) << 128 | callGasLimit),
            preVerificationGas: verificationGasLimit,
            gasFees: bytes32(uint256(maxPriorityFeePerGas) << 128 | maxFeePerGas),
            paymasterAndData: hex"",
            signature: hex""
        });
    }
}

/**
 * address sender
 *
 * Purpose: This field specifies the address of the smart contract account that intends to execute the operation. It is the account being controlled by this UserOperation.
 *
 * Significance: In the context of account abstraction, this sender is not an Externally Owned Account (EOA) but rather a smart contract wallet, such as our MinimalAccount example. This is the account that will ultimately perform the desired action.
 *
 * uint256 nonce
 *
 * Purpose: The nonce is a unique, sequential number used by the sender account to prevent replay attacks. Each UserOperation must have a unique nonce to ensure it's processed only once.
 *
 * Significance: Similar to the nonce used by EOAs to order transactions, this field ensures that malicious actors cannot resubmit a previously executed UserOperation. It acts as a sequence number for operations originating from the smart contract account, ensuring ordered and unique execution.
 *
 * bytes initCode
 *
 * Purpose: This field contains the bytecode necessary to deploy the sender smart contract account if it does not already exist. It typically includes the factory contract address and the constructor arguments for the new account.
 *
 * Significance: If the sender account already exists on the blockchain, initCode will be empty. This mechanism allows for counterfactual account deployment, where an account address can be determined and funded before its actual deployment. For scenarios dealing with already deployed accounts, this field can often be set to empty bytes.
 *
 * bytes callData
 *
 * Purpose: This is the core of the UserOperation, containing the actual instruction set for the sender account to execute. It usually consists of a function selector and ABI-encoded arguments for a function call.
 *
 * Significance: This field dictates what action the smart contract account will perform. For example, it could specify a call to the approve function on a token contract for a certain number of tokens, a transfer of assets, or any other interaction with the blockchain. This is effectively the "payload" or "intent" of the transaction.
 *
 * bytes32 accountGasLimits
 *
 * Purpose: This field contains packed gas limits relevant to the execution of the UserOperation by the account. It typically bundles verificationGasLimit (gas allocated for the validateUserOp function) and callGasLimit (gas allocated for executing the callData).
 *
 * Significance: Proper gas limit specification is crucial for ensuring the UserOperation can be processed without running out of gas during its validation or execution phases. These are the gas limits directly associated with the smart contract account's operations.
 *
 * uint256 preVerificationGas
 *
 * Purpose: This value represents the gas cost incurred before the validateUserOp function is called by the EntryPoint contract. It covers overheads like hashing the UserOperation, SLOADs from storage to fetch account nonces or check for existing deployments, and other preparatory steps performed by the bundler or EntryPoint.
 *
 * Significance: It ensures that the bundler (the entity submitting the UserOperation to the EntryPoint) is compensated for these preliminary gas expenses, which are not part of the validateUserOp or the main execution call.
 *
 * bytes32 gasFees
 *
 * Purpose: This field holds packed gas fee parameters, specifically maxFeePerGas and maxPriorityFeePerGas. These are analogous to the EIP-1559 gas parameters for standard Ethereum transactions.
 *
 * Significance: It allows the user to specify their willingness to pay for gas, influencing how quickly their UserOperation is picked up by bundlers and included in a block. These parameters manage the different gas fees associated with the transaction.
 *
 * bytes paymasterAndData
 *
 * Purpose: If a Paymaster is sponsoring the transaction (i.e., paying the gas fees on behalf of the user), this field contains the Paymaster's contract address and any additional data the Paymaster requires for its own validation logic (e.g., a signature from the user authorizing the Paymaster).
 *
 * Significance: This field is key to enabling gas abstraction. By default, the sender account must have sufficient funds to cover gas costs. However, with a Paymaster, a third party can cover these fees, meaning the user's smart contract account might not need to hold native currency. If no Paymaster is used, this field remains empty.
 *
 * bytes signature
 *
 * Purpose: This field contains the cryptographic signature that authenticates the UserOperation. The sender account's validateUserOp function is responsible for verifying this signature against a userOpHash. The userOpHash is a hash of the PackedUserOperation's fields, the EntryPoint contract's address, and the current chain ID.
 *
 * Significance: This is a critical security component. It proves that the owner of the sender account has authorized this specific operation. Account abstraction allows for flexible signature schemes beyond the standard ECDSA used by EOAs. The validateUserOp function in the smart contract account will implement custom logic to determine what constitutes a valid signature (e.g., multi-sig, social recovery mechanisms, passkeys, etc.). The inclusion of the EntryPoint address and chain ID in the signed data is crucial for preventing replay attacks across different chains or different EntryPoint contract implementations.
 *
 */
