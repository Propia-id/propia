// SPDX-License-Identifier: MIT
pragma solidity 0.8.31;

import {IBeacon} from "@openzeppelin/contracts/proxy/beacon/IBeacon.sol";
import {Ownable2Step, Ownable} from "@openzeppelin/contracts/access/Ownable2Step.sol";

/// @title SovraBeacon - Timelocked beacon for global wallet upgrades
/// @notice Stores the current wallet implementation address. The SovraDispatcher reads this
///         via `implementation()` for any wallet that has not pinned a per-account override.
///         Upgrades go through a 48-hour timelock so users can review and opt-out before activation.
///         A security council can bypass the timelock for critical patches via `emergencyUpgrade()`.
contract SovraBeacon is IBeacon, Ownable2Step {
    // ─── Errors ──────────────────────────────────────────

    /// @notice Thrown when the provided implementation address is the zero address.
    error InvalidImplementation();

    /// @notice Thrown when the provided address has no deployed code.
    error NotAContract();

    /// @notice Thrown when there is no pending upgrade to execute or cancel.
    error NoPendingUpgrade();

    /// @notice Thrown when executeUpgrade() is called before the timelock has elapsed.
    error TimelockNotElapsed();

    /// @notice Thrown when the caller is not the security council.
    error NotSecurityCouncil();

    /// @notice Thrown when the security council address is the zero address.
    error InvalidSecurityCouncil();

    // ─── Events ──────────────────────────────────────────

    /// @notice Emitted when a timelocked upgrade is scheduled.
    /// @param newImplementation The proposed new implementation address
    /// @param activationTime The earliest timestamp at which the upgrade can be executed
    event UpgradeScheduled(address indexed newImplementation, uint64 activationTime);

    /// @notice Emitted when a timelocked upgrade is executed after the delay.
    /// @param newImplementation The new active implementation address
    event UpgradeExecuted(address indexed newImplementation);

    /// @notice Emitted when a pending upgrade is cancelled by the owner.
    event UpgradeCancelled();

    /// @notice Emitted when the security council performs an immediate upgrade.
    /// @param newImplementation The new active implementation address
    event EmergencyUpgrade(address indexed newImplementation);

    /// @notice Emitted when the security council address is changed.
    /// @param previousCouncil The old security council address
    /// @param newCouncil The new security council address
    event SecurityCouncilUpdated(address indexed previousCouncil, address indexed newCouncil);

    // ─── Constants ───────────────────────────────────────

    /// @notice Timelock delay for standard upgrades (48 hours).
    uint64 public constant UPGRADE_DELAY = 48 hours;

    // ─── State ───────────────────────────────────────────

    /// @dev The current active implementation address.
    address private _implementation;

    /// @notice The address authorized to perform emergency (immediate) upgrades.
    address public securityCouncil;

    /// @notice The proposed implementation address for a pending timelocked upgrade.
    address public pendingImplementation;

    /// @notice The earliest timestamp at which the pending upgrade can be executed.
    uint64 public activationTime;

    // ─── Constructor ─────────────────────────────────────

    /// @param initialImpl The initial implementation contract address
    /// @param owner_ The owner (manages standard upgrades and council appointment)
    /// @param securityCouncil_ The security council address (can perform emergency upgrades)
    constructor(
        address initialImpl,
        address owner_,
        address securityCouncil_
    ) Ownable(owner_) {
        if (initialImpl == address(0)) revert InvalidImplementation();
        if (initialImpl.code.length == 0) revert NotAContract();
        if (securityCouncil_ == address(0)) revert InvalidSecurityCouncil();

        _implementation = initialImpl;
        securityCouncil = securityCouncil_;
    }

    // ─── IBeacon ─────────────────────────────────────────

    /// @inheritdoc IBeacon
    function implementation() external view override returns (address) {
        return _implementation;
    }

    // ─── Standard (Timelocked) Upgrade ───────────────────

    /// @notice Schedule an upgrade to a new implementation. Takes effect after UPGRADE_DELAY.
    /// @param newImplementation The proposed new implementation address
    function scheduleUpgrade(address newImplementation) external onlyOwner {
        _validateImplementation(newImplementation);

        pendingImplementation = newImplementation;
        activationTime = uint64(block.timestamp) + UPGRADE_DELAY;

        emit UpgradeScheduled(newImplementation, activationTime);
    }

    /// @notice Execute a previously scheduled upgrade after the timelock has elapsed.
    ///         Callable by anyone — the timelock is the access control.
    function executeUpgrade() external {
        if (pendingImplementation == address(0)) revert NoPendingUpgrade();
        if (block.timestamp < activationTime) revert TimelockNotElapsed();

        _implementation = pendingImplementation;

        emit UpgradeExecuted(pendingImplementation);

        delete pendingImplementation;
        delete activationTime;
    }

    /// @notice Cancel a pending timelocked upgrade.
    function cancelUpgrade() external onlyOwner {
        if (pendingImplementation == address(0)) revert NoPendingUpgrade();

        delete pendingImplementation;
        delete activationTime;

        emit UpgradeCancelled();
    }

    // ─── Emergency Upgrade ───────────────────────────────

    /// @notice Immediately upgrade the implementation, bypassing the timelock.
    ///         Only callable by the security council for critical security patches.
    /// @param newImplementation The new implementation address
    function emergencyUpgrade(address newImplementation) external {
        if (msg.sender != securityCouncil) revert NotSecurityCouncil();
        _validateImplementation(newImplementation);

        _implementation = newImplementation;

        // Clear any pending timelocked upgrade to avoid confusion
        if (pendingImplementation != address(0)) {
            delete pendingImplementation;
            delete activationTime;
        }

        emit EmergencyUpgrade(newImplementation);
    }

    // ─── Security Council Management ─────────────────────

    /// @notice Update the security council address. Only callable by the owner.
    /// @param newCouncil The new security council address
    function setSecurityCouncil(address newCouncil) external onlyOwner {
        if (newCouncil == address(0)) revert InvalidSecurityCouncil();

        emit SecurityCouncilUpdated(securityCouncil, newCouncil);
        securityCouncil = newCouncil;
    }

    // ─── Internal ────────────────────────────────────────

    /// @dev Validates that the implementation address is non-zero and has code.
    function _validateImplementation(address impl) internal view {
        if (impl == address(0)) revert InvalidImplementation();
        if (impl.code.length == 0) revert NotAContract();
    }
}
