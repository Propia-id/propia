// SPDX-License-Identifier: MIT
pragma solidity 0.8.31;

/// @title SovraDispatcher - Permanent thin proxy for EIP-7702 delegated EOAs
/// @notice After EIP-7702 delegation, the EOA's code points to this dispatcher.
///         All calls are forwarded via delegatecall to the implementation contract.
///         If the ERC-1967 implementation slot is empty (fresh delegation, pre-initialize),
///         the dispatcher falls back to an immutable default implementation embedded in bytecode.
///         This works because EIP-7702 delegates to bytecode, which includes immutables.
/// @dev No admin, no owner, no upgradeable storage of its own. The implementation
///      contract controls upgrades via its upgrade() function writing to the ERC-1967 slot.
contract SovraDispatcher {
    /// @dev ERC-1967 implementation storage slot:
    ///      bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1)
    bytes32 internal constant IMPL_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    /// @dev Default implementation address, used when ERC-1967 slot is 0 (pre-initialize).
    ///      Embedded in bytecode as an immutable, so it survives EIP-7702 delegation.
    address internal immutable _defaultImpl;

    /// @param defaultImpl The initial implementation address to use before the ERC-1967 slot is set
    constructor(address defaultImpl) {
        _defaultImpl = defaultImpl;
    }

    /// @notice Forwards all calls to the implementation via delegatecall.
    ///         Reads implementation from ERC-1967 slot; uses immutable default if slot is empty.
    fallback() external payable {
        address defaultImpl = _defaultImpl;
        assembly {
            let impl := sload(IMPL_SLOT)
            if iszero(impl) {
                impl := defaultImpl
            }
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    /// @notice Accepts plain ETH transfers.
    receive() external payable {}
}
