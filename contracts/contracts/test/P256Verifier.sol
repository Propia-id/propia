// SPDX-License-Identifier: MIT
pragma solidity 0.8.31;

import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";

/// @title P256Verifier - Test-only mock for the EIP-7212 precompile at address(0x0100)
/// @notice Implements the EIP-7212 interface in Solidity using OpenZeppelin's P256 library.
///         Input: 160 bytes raw concatenation (hash || r || s || x || y).
///         Output: abi-encoded uint256(1) on valid signature, uint256(0) otherwise.
/// @dev This contract is ONLY for Hardhat local tests where the precompile doesn't exist.
///      Its deployed bytecode is etched at 0x0100 via hardhat_setCode in test setup.
///      Production on the ethrex L2 uses the native precompile — this contract is never deployed there.
contract P256Verifier {
    /// @notice Verifies a P256 signature. Called via staticcall with raw 160-byte input.
    /// @param input 160 bytes: hash (32) || r (32) || s (32) || x (32) || y (32)
    /// @return abi-encoded uint256(1) if valid, uint256(0) if invalid or malformed input
    fallback(bytes calldata input) external returns (bytes memory) {
        if (input.length != 160) {
            return abi.encode(uint256(0));
        }

        bytes32 hash = bytes32(input[0:32]);
        bytes32 r = bytes32(input[32:64]);
        bytes32 s = bytes32(input[64:96]);
        bytes32 x = bytes32(input[96:128]);
        bytes32 y = bytes32(input[128:160]);

        if (P256.verify(hash, r, s, x, y)) {
            return abi.encode(uint256(1));
        }
        return abi.encode(uint256(0));
    }
}
