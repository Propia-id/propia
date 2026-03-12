// SPDX-License-Identifier: MIT
pragma solidity 0.8.31;

/// @title ReentrancyAttacker - Test contract that attempts to reenter SovraWalletV1.execute()
/// @dev Used only in tests to verify the reentrancy guard works correctly.
contract ReentrancyAttacker {
    address public wallet;
    bool public attacked;

    function setWallet(address _wallet) external {
        wallet = _wallet;
    }

    /// @dev When receiving ETH, attempt to reenter wallet.execute() with garbage args.
    ///      The reentrancy guard should revert before signature verification.
    receive() external payable {
        if (!attacked) {
            attacked = true;
            // Attempt reentrant call to execute() with garbage signature
            (bool success,) = wallet.call(
                abi.encodeWithSignature(
                    "execute(address,uint256,bytes,bytes32,bytes32)",
                    address(this),
                    0,
                    "",
                    bytes32(uint256(1)),
                    bytes32(uint256(2))
                )
            );
            // Store result for test assertion
            assembly {
                sstore(2, success) // slot 2 = reentrantCallSucceeded
            }
        }
    }

    function reentrantCallSucceeded() external view returns (bool result) {
        assembly {
            result := sload(2)
        }
    }
}
