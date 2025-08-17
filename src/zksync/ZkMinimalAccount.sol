// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

// zkSync Era Imports
import {
    IAccount,
    ACCOUNT_VALIDATION_SUCCESS_MAGIC
} from "lib/foundry-era-contracts/src/system-contracts/contracts/interfaces/IAccount.sol";
import {
    Transaction,
    MemoryTransactionHelper
} from "lib/foundry-era-contracts/src/system-contracts/contracts/libraries/MemoryTransactionHelper.sol";
import {SystemContractsCaller} from
    "lib/foundry-era-contracts/src/system-contracts/contracts/libraries/SystemContractsCaller.sol";
import {
    NONCE_HOLDER_SYSTEM_CONTRACT,
    BOOTLOADER_FORMAL_ADDRESS,
    DEPLOYER_SYSTEM_CONTRACT
} from "lib/foundry-era-contracts/src/system-contracts/contracts/Constants.sol";
import {INonceHolder} from "lib/foundry-era-contracts/src/system-contracts/contracts/interfaces/INonceHolder.sol";
import {Utils} from "lib/foundry-era-contracts/src/system-contracts/contracts/libraries/Utils.sol";

// OZ Imports
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/**
 * Lifecycle of a type 113 (0x71) transaction
 * msg.sender is the bootloader system contract
 *
 * Phase 1 Validation
 * 1. The user sends the transaction to the "zkSync API client" (sort of a "light node")
 * 2. The zkSync API client checks to see the the nonce is unique by querying the NonceHolder system contract
 * 3. The zkSync API client calls validateTransaction, which MUST update the nonce
 * 4. The zkSync API client checks the nonce is updated
 * 5. The zkSync API client calls payForTransaction, or prepareForPaymaster & validateAndPayForPaymasterTransaction
 * 6. The zkSync API client verifies that the bootloader gets paid
 *
 * Phase 2 Execution
 * 7. The zkSync API client passes the validated transaction to the main node / sequencer (as of today, they are the same)
 * 8. The main node calls executeTransaction
 * 9. If a paymaster was used, the postTransaction is called
 */

// ZkMinimalAccount is the implementation of IAccount, as the reference point
contract ZkMinimalAccount is IAccount, Ownable {
    using MemoryTransactionHelper for Transaction;

    error ZkMinimalAccount__NotEnoughBalance();
    error ZkMinimalAccount__NotFromBootLoader();
    error ZkMinimalAccount__ExecutionFailed();
    error ZkMinimalAccount__NotFromBootLoaderOrOwner();
    error ZkMinimalAccount__FailedToPay();
    error ZkMinimalAccount__InvalidSignature();

    // BOOTLOADER_FORMAL_ADDRESS is a constant representing the official address of the zkSync Bootloader.

    modifier requireFromBootLoader() {
        if (msg.sender != BOOTLOADER_FORMAL_ADDRESS) {
            revert ZkMinimalAccount__NotFromBootLoader();
        }
        _;
    }

    modifier requireFromBootLoaderOrOwner() {
        if (msg.sender != BOOTLOADER_FORMAL_ADDRESS && msg.sender != owner()) {
            revert ZkMinimalAccount__NotFromBootLoaderOrOwner();
        }
        _;
    }

    constructor() Ownable(msg.sender) {}

    receive() external payable {}

    /**
     * @notice must increase the nonce
     * @notice must validate the transaction (check the owner signed the transaction)
     * @notice also check to see if we have enough money in our account
     */
    /**
     * @notice Purpose of validateTransaction
     * This is arguably the most critical function for account abstraction.
     * It's responsible for validating whether the account agrees to process the given transaction and, crucially, if it's willing to pay for it (or if a paymaster will).
     * This involves checking the transaction's signature against the account's custom authentication logic, verifying the nonce, and ensuring sufficient funds for gas.
     *
     * @notice Analogy to EIP-4337
     * This function is analogous to the validateUserOp function in an EIP-4337 smart contract wallet.
     *
     * @notice Parameters
     *
     * _txHash: The hash of the transaction, potentially used by explorers or for off-chain tracking.
     *
     * _suggestedSignedHash: A hash related to how EOAs would sign the transaction, used by the Bootloader. Typically ignored in basic smart account implementations.
     *
     * _transaction: The Transaction struct (often changed to memory in implementations like ZkMinimalAccount.sol) containing all details of the transaction to be validated.
     *
     * @return magic A magic value indicates the outcome of the validation.
     *
     * For successful validation, the function must return IAccount.validateTransaction.selector
     */
    function validateTransaction(bytes32, /*_txHash*/ bytes32, /*_suggestedSignedHash*/ Transaction memory _transaction)
        external
        payable
        requireFromBootLoader
        returns (bytes4 magic)
    {
        return _validateTransaction(_transaction);
    }

    /**
     * @notice Purpose of executeTransaction
     * This function executes the actual logic of the transaction.
     * After successful validation, this function is called to perform the intended operations,
     * such as making a call to another contract, transferring tokens, etc., as specified in _transaction.to, _transaction.value, and _transaction.data.
     *
     * @notice Analogy to EIP-4337
     * This is similar to the execute or executeBatch functions found in EIP-4337 smart contract wallets.
     *
     * @notice Invocation
     * This function would typically be called by a "higher admin" (like the Bootloader in the standard flow)
     * or directly by the account owner if they are an EOA capable of bypassing the standard AA validation flow (though the standard flow via validation is preferred for smart contract accounts).
     *
     * @notice Parameters
     * The _txHash and _suggestedSignedHash parameters are, again, primarily for the Bootloader and are generally ignored in the core logic of a minimal account implementation.
     * The _transaction struct contains all necessary information for execution.
     */
    function executeTransaction(bytes32, /*_txHash*/ bytes32, /*_suggestedSignedHash*/ Transaction memory _transaction)
        external
        payable
        requireFromBootLoaderOrOwner
    {
        _executeTransaction(_transaction);
    }

    /**
     * @notice Purpose of executeTransactionFromOutside
     * This function allows an external party (e.g., a relayer, a friend, or even another contract) to
     * submit and trigger the execution of a transaction that has already been signed by the account owner
     * and validated through a separate mechanism or by the nature of the transaction's construction (e.g., signature is part of _transaction.signature).
     *
     * @notice Key Distinction
     * The IAccount.sol comments explicitly state: "There is no point in providing possible signed hash in the executeTransactionFromOutside method, since it typically should not be trusted."
     * This implies that the transaction passed here is expected to be self-contained and verifiable, perhaps because its signature is already included within the _transaction.signature field
     * and the account's logic for this function will re-verify it.
     *
     * @notice Analogy to EIP-4337
     * This function is conceptually what an EIP-4337 EntryPoint contract would call on a smart wallet after validateUserOp has succeeded and the EntryPoint is ready to execute the UserOperation
     *
     * @notice Use Case Example:
     * You, as the account owner, sign a transaction off-chain (the full Transaction struct including your signature).
     * You then provide this signed Transaction data to a friend. Your friend can then call executeTransactionFromOutside on your smart contract wallet, submitting your pre-signed transaction.
     * Your account's implementation of this function would then verify your signature from _transaction.signature and execute the call.
     */
    function executeTransactionFromOutside(Transaction memory _transaction) external payable {
        bytes4 magic = _validateTransaction(_transaction);
        if (magic != ACCOUNT_VALIDATION_SUCCESS_MAGIC) {
            revert ZkMinimalAccount__InvalidSignature();
        }
        _executeTransaction(_transaction);
    }

    /**
     * @notice Purpose of payForTransaction
     * This function handles the payment logic for the transaction. It's where the account (or, by extension, a paymaster it interacts with) actually disburses the funds to cover the transaction fees.
     * The msg.value sent with this call would typically be used to cover these costs.
     *
     * @notice Analogy to EIP-4337
     *  This is similar to the internal _payPrefund function or the logic within an EntryPoint that deducts fees from the smart wallet's deposit in EIP-4337 implementations.
     *
     * @notice Native Fee Handling
     * In ZK Sync, because AA is native, the protocol can directly manage fee payments from the account after successful validation, often making this function's explicit call part of the Bootloader's orchestrated flow.
     */
    function payForTransaction(bytes32, /*_txHash*/ bytes32, /*_suggestedSignedHash*/ Transaction memory _transaction)
        external
        payable
    {
        bool success = _transaction.payToTheBootloader();
        if (!success) {
            revert ZkMinimalAccount__FailedToPay();
        }
    }

    /**
     * @notice Purpose of prepareForPaymaster
     * This function is invoked if a paymaster is involved in the transaction (i.e., _transaction.paymaster is not address zero).
     * It's called before payForTransaction and allows the account to perform any necessary preparations or approvals related to the paymaster.
     * This could involve verifying the paymaster, checking allowances, or setting specific states.
     *
     * @notice Native Paymasters
     * ZK Sync natively supports paymasters. A paymaster is an entity (another smart contract) that can sponsor transactions by paying fees on behalf of the user.
     * The _transaction.paymasterInput field provides data for the paymaster's specific logic. This function ensures the account is ready for the paymaster's involvement.
     *
     * @notice Parameters
     * _possibleSignedHash is another Bootloader-related parameter. The crucial part is the interaction logic based on _transaction.paymaster and _transaction.paymasterInput.
     */
    function prepareForPaymaster(bytes32 _txHash, bytes32 _possibleSignedHash, Transaction memory _transaction)
        external
        payable
    {}

    function _validateTransaction(Transaction memory _transaction) internal returns (bytes4 magic) {
        // Call nonceholder
        // increment nonce
        // call(x, y, z) -> system contract call
        SystemContractsCaller.systemCallWithPropagatedRevert(
            uint32(gasleft()),
            address(NONCE_HOLDER_SYSTEM_CONTRACT),
            0,
            abi.encodeCall(INonceHolder.incrementMinNonceIfEquals, (_transaction.nonce))
        );

        // Check for fee to pay
        uint256 totalRequiredBalance = _transaction.totalRequiredBalance();
        if (totalRequiredBalance > address(this).balance) {
            revert ZkMinimalAccount__NotEnoughBalance();
        }

        // Check the signature
        bytes32 txHash = _transaction.encodeHash(); // _transaction.encodeHash() provides the appropriate EIP-712 digest for AA transactions, or the correct hash for other transaction types if they were being processed by the account
        address signer = ECDSA.recover(txHash, _transaction.signature);
        bool isValidSigner = signer == owner();
        if (isValidSigner) {
            magic = ACCOUNT_VALIDATION_SUCCESS_MAGIC;
        } else {
            magic = bytes4(0);
        }
        return magic;
    }

    function _executeTransaction(Transaction memory _transaction) internal {
        address to = address(uint160(_transaction.to));
        uint128 value = Utils.safeCastToU128(_transaction.value);
        bytes memory data = _transaction.data;

        if (to == address(DEPLOYER_SYSTEM_CONTRACT)) {
            uint32 gas = Utils.safeCastToU32(gasleft());
            SystemContractsCaller.systemCallWithPropagatedRevert(gas, to, value, data);
        } else {
            bool success;
            assembly ("memory-safe") {
                success := call(gas(), to, value, add(data, 0x20), mload(data), 0, 0)
            }
            if (!success) {
                revert ZkMinimalAccount__ExecutionFailed();
            }
        }
    }
}
