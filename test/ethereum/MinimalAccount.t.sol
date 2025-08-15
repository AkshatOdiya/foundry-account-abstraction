// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {MinimalAccount} from "src/ethereum/MinimalAccount.sol";
import {DeployMinimal} from "script/DeployMinimalAccount.s.sol";
import {HelperConfig} from "script/HelperConfig.s.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";
import {SendPackedUserOp, PackedUserOperation} from "script/SendPackedUserOps.s.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract MinimalAccountTest is Test {
    using MessageHashUtils for bytes32;

    DeployMinimal deployMinimal;
    HelperConfig helperConfig;
    MinimalAccount minimalAccount;
    SendPackedUserOp sendPackedUserOp;
    ERC20Mock usdc;
    uint256 constant AMOUNT = 1e18;
    address immutable i_randomUser = makeAddr("randomUser");

    function setUp() public {
        deployMinimal = new DeployMinimal();
        (helperConfig, minimalAccount) = deployMinimal.deployMinimalAccount();
        usdc = new ERC20Mock();
        sendPackedUserOp = new SendPackedUserOp();
    }

    // USDC Approval

    // msg.sender -> MinimalAccount
    // approve some amount
    // usdc contract
    // come from entrypoint

    function testOwnerCanExecute() public {
        // Arrange
        assertEq(usdc.balanceOf(address(minimalAccount)), 0);
        address dest = address(usdc);
        uint256 value = 0;
        bytes memory functionData = abi.encodeWithSelector(ERC20Mock.mint.selector, address(minimalAccount), AMOUNT);
        // Act
        vm.prank(minimalAccount.owner());
        minimalAccount.execute(dest, value, functionData);
        // Assert
        assertEq(usdc.balanceOf(address(minimalAccount)), AMOUNT);
    }

    function testRecoverSignedOp() public {
        // Arrange
        address dest = address(usdc);
        uint256 value = 0;
        bytes memory functionData = abi.encodeWithSelector(ERC20Mock.mint.selector, address(minimalAccount), AMOUNT);

        // Define the callData for MinimalAccount.execute
        // This is what the EntryPoint will use to call our smart account.
        bytes memory executeCallData =
            abi.encodeWithSelector(MinimalAccount.execute.selector, dest, value, functionData);

        // Generate the signed PackedUserOperation
        PackedUserOperation memory packedUserOp = sendPackedUserOp.generatedSignedUserOperation(
            executeCallData, helperConfig.getConfig(), address(minimalAccount)
        );

        // Get the userOpHash again (as the EntryPoint would calculate it)
        // Ensure we use the same EntryPoint address as used during signing.
        bytes32 userOperationHash = IEntryPoint(helperConfig.getConfig().entryPoint).getUserOpHash(packedUserOp);

        // Act
        // Recover the signer's address from the EIP-191 compliant digest and the signature.
        // The digest MUST match what was signed.
        address actualSigner = ECDSA.recover(userOperationHash.toEthSignedMessageHash(), packedUserOp.signature);

        // Assert
        assertEq(actualSigner, minimalAccount.owner(), "Signer recovery failed");
    }

    // 1. Sign user ops
    // 2. Call validate userops
    // 3. Assert the return is correct
    function testValidationOfUserOps() public {
        address dest = address(usdc);
        uint256 value = 0;
        bytes memory functionData = abi.encodeWithSelector(ERC20Mock.mint.selector, address(minimalAccount), AMOUNT);
        bytes memory executeCallData =
            abi.encodeWithSelector(MinimalAccount.execute.selector, dest, value, functionData);
        PackedUserOperation memory packedUserOp = sendPackedUserOp.generatedSignedUserOperation(
            executeCallData, helperConfig.getConfig(), address(minimalAccount)
        );
        bytes32 userOperationHash = IEntryPoint(helperConfig.getConfig().entryPoint).getUserOpHash(packedUserOp);

        // missingAccountFunds: This parameter is part of the validateUserOp signature and relates to the pre-funding mechanism where the account might need to compensate the EntryPoint for gas
        uint256 missingAccountFunds = 1e18;

        // Act
        vm.prank(address(helperConfig.getConfig().entryPoint));
        uint256 validationData = minimalAccount.validateUserOp(packedUserOp, userOperationHash, missingAccountFunds);

        // Assert
        assertEq(validationData, 0); // 0 represents success
    }

    /**
     * @notice testEntryPointCanExecuteCommands
     * This test shows, how a bundler(alt-mempool) interacts with the
     * EntryPoint to get a UserOperation processed and executed by the target smart contract account.
     */
    function testEntryPointCanExecute() public {
        address dest = address(usdc);
        uint256 value = 0;
        bytes memory functionData = abi.encodeWithSelector(ERC20Mock.mint.selector, address(minimalAccount), AMOUNT);
        bytes memory executeCallData =
            abi.encodeWithSelector(MinimalAccount.execute.selector, dest, value, functionData);
        PackedUserOperation memory packedUserOp = sendPackedUserOp.generatedSignedUserOperation(
            executeCallData, helperConfig.getConfig(), address(minimalAccount)
        );
        // bytes32 userOperationHash = IEntryPoint(helperConfig.getConfig().entryPoint).getUserOpHash(packedUserOp);

        /**
         * @notice why vm.deal ?
         * the EntryPoint contract needs to withdraw funds from the minimalAccount to
         * compensate the bundler (represented by randomUser in our test) for the gas costs incurred in processing the UserOperation.
         */
        vm.deal(address(minimalAccount), AMOUNT);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = packedUserOp;

        // Act
        vm.prank(i_randomUser); // this will act as our alt mempool(bundler) node

        /**
         * @notice The second component in handleOps is beneficiary account, waht it is?
         * beneficiary: This is the address that will receive the gas fee compensation for successfully processing the UserOperation(s).
         * In our test, this is the randomUser (our simulated bundler).
         */
        IEntryPoint(helperConfig.getConfig().entryPoint).handleOps(ops, payable(i_randomUser));

        // Assert
        assertEq(usdc.balanceOf(address(minimalAccount)), AMOUNT);
    }
}
