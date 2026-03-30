// SPDX-License-Identifier: MIT
pragma solidity 0.8.31;

/// @title SovraDispatcher - Permanent thin proxy for EIP-7702 delegated EOAs
/// @notice After EIP-7702 delegation, the EOA's code points to this dispatcher.
///         All calls are forwarded via delegatecall to the implementation contract.
///         Resolution order:
///           1. ERC-1967 implementation slot (per-account pin via upgrade())
///           2. Beacon (global default via IBeacon.implementation())
///         Users who call upgrade() opt out of beacon-managed upgrades.
///         Users who call resetToBeacon() clear their pin and follow the beacon again.
/// @dev No admin, no owner, no upgradeable storage of its own. The implementation
///      contract controls per-account upgrades via its upgrade() function writing
///      to the ERC-1967 slot. The beacon controls the global default.
contract SovraDispatcher {
    /// @notice Thrown when the resolved implementation address is the zero address.
    error NoImplementation();
    /// @dev ERC-1967 implementation storage slot:
    ///      bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1)
    bytes32 internal constant IMPL_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    /// @dev Beacon contract address — immutable, survives EIP-7702 delegation.
    ///      When the ERC-1967 slot is empty, the dispatcher calls beacon.implementation()
    ///      to resolve the current global implementation.
    address internal immutable _beacon;

    /// @param beacon The beacon contract that provides the global default implementation
    constructor(address beacon) {
        _beacon = beacon;
    }

    /// @notice Forwards all calls to the implementation via delegatecall.
    ///         Reads implementation from ERC-1967 slot; queries beacon if slot is empty.
    fallback() external payable {
        address beacon = _beacon;
        assembly {
            let impl := sload(IMPL_SLOT)
            if iszero(impl) {
                // IBeacon.implementation() selector: 0x5c60da1b
                mstore(0x00, 0x5c60da1b00000000000000000000000000000000000000000000000000000000)
                let ok := staticcall(gas(), beacon, 0x00, 0x04, 0x00, 0x20)
                if iszero(ok) { revert(0, 0) }
                impl := mload(0x00)
                // NoImplementation() selector: 0xc6745ca8
                if iszero(impl) {
                    mstore(0x00, 0xc6745ca800000000000000000000000000000000000000000000000000000000)
                    revert(0x00, 0x04)
                }
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
