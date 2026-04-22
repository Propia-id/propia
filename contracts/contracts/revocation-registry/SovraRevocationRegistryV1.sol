// SPDX-License-Identifier: MIT
pragma solidity 0.8.31;

import {ISovraRevocationRegistry} from "./ISovraRevocationRegistry.sol";
import {ISovraIssuerRegistry} from "../issuer-registry/ISovraIssuerRegistry.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/// @title SovraRevocationRegistryV1 - UUPS-upgradeable credential status registry
/// @notice Stores per-issuer, per-purpose bitmaps for credential revocation and suspension.
///         STATUS_MANAGER_ROLE flips bits; UPGRADER_ROLE manages upgrades.
///         Bitmaps are lazily allocated — storage slots are only written when bits are set.
///         getBitmap() pads to 512 slots (131,072 bits) in memory for W3C herd-privacy compliance.
contract SovraRevocationRegistryV1 is ISovraRevocationRegistry, AccessControlUpgradeable, UUPSUpgradeable {
    // ─── Constants ─────────────────────────────────────

    /// @notice Purpose value for permanent revocation.
    uint8 public constant REVOCATION = 0;

    /// @notice Purpose value for reversible suspension.
    uint8 public constant SUSPENSION = 1;

    /// @notice Minimum bitmap size in uint256 slots (512 × 256 = 131,072 bits).
    uint256 internal constant MIN_BITMAP_SLOTS = 512;

    // ─── Roles ─────────────────────────────────────────

    /// @notice Role that can initialize bitmaps and change credential status bits.
    bytes32 public constant STATUS_MANAGER_ROLE = keccak256("STATUS_MANAGER_ROLE");

    /// @notice Role that can perform UUPS upgrades.
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    // ─── Storage ────────────────────────────────────────

    /// @notice Reference to the Issuer Registry for cross-contract validation.
    ISovraIssuerRegistry public issuerRegistry;

    /// @dev issuer => purpose => bitmap words. Lazily allocated — grows via push().
    mapping(address => mapping(uint8 => uint256[])) internal bitmaps;

    /// @dev issuer => purpose => whether initializeBitmap has been called.
    mapping(address => mapping(uint8 => bool)) internal initialized;

    // ─── Constructor ────────────────────────────────────

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // ─── Initialization ─────────────────────────────────

    /// @notice Initialize the registry with an admin and a reference to the Issuer Registry.
    /// @param admin The initial admin address (receives all roles)
    /// @param issuerRegistryAddr Address of the deployed SovraIssuerRegistry proxy
    function initialize(address admin, address issuerRegistryAddr) external initializer {
        __AccessControl_init();
        __UUPSUpgradeable_init();
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(STATUS_MANAGER_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);
        issuerRegistry = ISovraIssuerRegistry(issuerRegistryAddr);
    }

    // ─── UUPS ───────────────────────────────────────────

    /// @dev Restricts upgrades to accounts with UPGRADER_ROLE.
    function _authorizeUpgrade(address) internal override onlyRole(UPGRADER_ROLE) {}

    // ─── Bitmap Management ──────────────────────────────

    /// @inheritdoc ISovraRevocationRegistry
    function initializeBitmap(address issuer, uint8 purpose) external onlyRole(STATUS_MANAGER_ROLE) {
        _validatePurpose(purpose);
        if (!issuerRegistry.isRegistered(issuer)) revert IssuerNotRegistered();
        if (initialized[issuer][purpose]) revert BitmapAlreadyInitialized();

        initialized[issuer][purpose] = true;

        emit BitmapInitialized(issuer, purpose);
    }

    /// @inheritdoc ISovraRevocationRegistry
    function setStatus(address issuer, uint8 purpose, uint256 index) external onlyRole(STATUS_MANAGER_ROLE) {
        _requireInitialized(issuer, purpose);
        _setBit(issuer, purpose, index);

        emit StatusChanged(issuer, purpose, index, true);
    }

    /// @inheritdoc ISovraRevocationRegistry
    function clearStatus(address issuer, uint8 purpose, uint256 index) external onlyRole(STATUS_MANAGER_ROLE) {
        if (purpose == REVOCATION) revert CannotUnrevoke();
        _requireInitialized(issuer, purpose);
        _clearBit(issuer, purpose, index);

        emit StatusChanged(issuer, purpose, index, false);
    }

    /// @inheritdoc ISovraRevocationRegistry
    function batchSetStatus(
        address issuer,
        uint8 purpose,
        uint256[] calldata indices
    ) external onlyRole(STATUS_MANAGER_ROLE) {
        _requireInitialized(issuer, purpose);

        for (uint256 i = 0; i < indices.length; i++) {
            _setBit(issuer, purpose, indices[i]);
            emit StatusChanged(issuer, purpose, indices[i], true);
        }
    }

    // ─── Queries ────────────────────────────────────────

    /// @inheritdoc ISovraRevocationRegistry
    function getStatus(address issuer, uint8 purpose, uint256 index) external view returns (bool) {
        _validatePurpose(purpose);
        uint256 slot = index / 256;
        uint256 bit = index % 256;

        uint256[] storage bitmap = bitmaps[issuer][purpose];
        if (slot >= bitmap.length) return false;

        return (bitmap[slot] >> bit) & 1 == 1;
    }

    /// @inheritdoc ISovraRevocationRegistry
    function getBitmap(address issuer, uint8 purpose) external view returns (uint256[] memory) {
        _validatePurpose(purpose);
        uint256[] storage bitmap = bitmaps[issuer][purpose];
        uint256 storageLen = bitmap.length;
        uint256 returnLen = storageLen < MIN_BITMAP_SLOTS ? MIN_BITMAP_SLOTS : storageLen;

        uint256[] memory result = new uint256[](returnLen);
        for (uint256 i = 0; i < storageLen; i++) {
            result[i] = bitmap[i];
        }
        // Remaining slots are already zero-initialized by Solidity

        return result;
    }

    // ─── Internal ───────────────────────────────────────

    function _validatePurpose(uint8 purpose) internal pure {
        if (purpose > SUSPENSION) revert InvalidPurpose();
    }

    function _requireInitialized(address issuer, uint8 purpose) internal view {
        _validatePurpose(purpose);
        if (!initialized[issuer][purpose]) revert BitmapNotInitialized();
    }

    /// @dev Set a bit to 1. Extends the array with zero-valued slots if needed.
    function _setBit(address issuer, uint8 purpose, uint256 index) internal {
        uint256 slot = index / 256;
        uint256 bit = index % 256;

        uint256[] storage bitmap = bitmaps[issuer][purpose];

        // Extend array if the target slot doesn't exist yet
        while (bitmap.length <= slot) {
            bitmap.push(0);
        }

        bitmap[slot] |= (1 << bit);
    }

    /// @dev Clear a bit to 0. No-op if the slot doesn't exist (bit is already 0).
    function _clearBit(address issuer, uint8 purpose, uint256 index) internal {
        uint256 slot = index / 256;
        uint256 bit = index % 256;

        uint256[] storage bitmap = bitmaps[issuer][purpose];
        if (slot >= bitmap.length) return; // Already 0

        bitmap[slot] &= ~(1 << bit);
    }
}
