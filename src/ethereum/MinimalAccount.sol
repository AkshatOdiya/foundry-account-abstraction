// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IAccount} from "lib/account-abstraction/contracts/interfaces/IAccount.sol";
import {PackedUserOperation} from "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "lib/account-abstraction/contracts/core/Helpers.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";

// MinimalAccount will pretend to be our EOA
contract MinimalAccount is IAccount, Ownable {
    error MinimalAccount__NotFromEntryPoint();
    error MinimalAccount__NotFromEntryPointOrOwner();
    error MinimalAccount__TransferFailed(bytes recepient);

    IEntryPoint private immutable i_entryPoint;

    modifier requireFromEntryPoint() {
        if (msg.sender != address(i_entryPoint)) {
            revert MinimalAccount__NotFromEntryPoint();
        }
        _;
    }

    modifier requireFromEntryPointOrOwner() {
        if (msg.sender != address(i_entryPoint) && msg.sender != owner()) {
            revert MinimalAccount__NotFromEntryPointOrOwner();
        }
        _;
    }

    constructor(address entryPoint) Ownable(msg.sender) {
        i_entryPoint = IEntryPoint(entryPoint);
    }

    // An account should also accept funds
    receive() external payable {}

    /**
     * @param userOp  The packed UserOperation data
     * @param userOpHash  A hash of the userOp, used as the basis for the signature
     * @param missingAccountFunds Funds needed for the operation if the account hasn't pre-deposited enough into the EntryPoint
     * @return validationData Returns data indicating validity and optional time constraints
     *
     * This function is invoked by the EntryPoint contract before any execution takes place.
     * Verify the user's signature, which is part of the userOp struct, against the userOpHash.
     *
     * Validate the nonce to prevent replay attacks.
     *
     * Perform any other necessary checks (e.g., account active, not locked).
     *
     * If validateUserOp completes successfully (doesn't revert), the EntryPoint proceeds to execute the operation.
     * If it reverts, the operation is rejected. The validationData return value can be used to encode more complex validation logic,
     * such as specifying time windows during which the UserOperation is valid (particularly useful for Paymaster interactions).
     * A return value of 0 typically indicates successful validation without time constraints.
     */
    // A Signature is valid, if it's the MinimalAccount owner
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        requireFromEntryPoint
        returns (uint256 validationData)
    {
        validationData = _validateSignature(userOp, userOpHash);
        _payPrefund(missingAccountFunds);
    }

    function execute(address dest, uint256 value, bytes calldata funcData) external requireFromEntryPointOrOwner {
        (bool success, bytes memory result) = dest.call{value: value}(funcData);
        if (!success) {
            revert MinimalAccount__TransferFailed(result);
        }
    }

    function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        view
        returns (uint256 validationData)
    {
        bytes32 ethSignedMessageHash = MessageHashUtils.toEthSignedMessageHash(userOpHash);
        address signer = ECDSA.recover(ethSignedMessageHash, userOp.signature);
        if (signer != owner()) {
            return SIG_VALIDATION_FAILED; // SIG_VALIDATION_FAILED = 1
        }
        return SIG_VALIDATION_SUCCESS; // SIG_VALIDATION_SUCCESS = 0
    }

    // function to send funds to entryPoint as fee for preceeding
    function _payPrefund(uint256 missingAccountFunds) internal {
        // function validateUserOp can only be callable by entryPoint contract therefore, msg.sender(entryPoint contract) is payable
        if (missingAccountFunds != 0) {
            (bool success,) = payable(msg.sender).call{value: missingAccountFunds, gas: type(uint256).max}("");
            (success);
        }
    }

    function getEntryPoint() external view returns (address) {
        return address(i_entryPoint);
    }
}
