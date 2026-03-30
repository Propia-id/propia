// SPDX-License-Identifier: MIT
pragma solidity 0.8.31;

import {ISovraIssuerRegistry} from "./ISovraIssuerRegistry.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/// @title SovraIssuerRegistryV1 - UUPS-upgradeable issuer trust registry
/// @notice Stores which issuers are trusted for which credential types.
///         ISSUER_MANAGER_ROLE manages issuers; UPGRADER_ROLE manages upgrades;
///         DEFAULT_ADMIN_ROLE grants and revokes roles. Verifiers query via isTrusted().
contract SovraIssuerRegistryV1 is ISovraIssuerRegistry, AccessControlUpgradeable, UUPSUpgradeable {
    // ─── Roles ─────────────────────────────────────────

    /// @notice Role that can register/remove issuers and manage credential types.
    bytes32 public constant ISSUER_MANAGER_ROLE = keccak256("ISSUER_MANAGER_ROLE");

    /// @notice Role that can perform UUPS upgrades.
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    // ─── Storage ────────────────────────────────────────

    /// @notice On-chain record for a registered issuer.
    /// @param registered Whether the issuer is currently active in the registry
    /// @param trustedFor Mapping from credential type hash to trust status
    struct IssuerRecord {
        bool registered;
        mapping(bytes32 => bool) trustedFor;
    }

    /// @dev Issuer address → on-chain record (registration status + per-type trust).
    mapping(address => IssuerRecord) internal issuers;

    /// @notice All registered issuer addresses, for enumeration.
    address[] public issuerList;

    /// @notice All known credential type hashes, for enumeration.
    bytes32[] public credentialTypes;

    /// @inheritdoc ISovraIssuerRegistry
    mapping(bytes32 => bool) public knownType;


    // ─── Constructor ────────────────────────────────────

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // ─── Initialization ─────────────────────────────────

    /// @notice Initialize the registry with an admin. Called once via proxy.
    /// @param admin The initial admin address (receives all roles)
    function initialize(address admin) external initializer {
        __AccessControl_init();
        __UUPSUpgradeable_init();
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ISSUER_MANAGER_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);
    }

    // ─── UUPS ───────────────────────────────────────────

    /// @dev Restricts upgrades to accounts with UPGRADER_ROLE.
    function _authorizeUpgrade(address) internal override onlyRole(UPGRADER_ROLE) {}

    // ─── Issuer Management ──────────────────────────────

    /// @inheritdoc ISovraIssuerRegistry
    function registerIssuer(
        address issuer,
        bytes32[] calldata credentialTypeIds
    ) external onlyRole(ISSUER_MANAGER_ROLE) {
        if (issuers[issuer].registered) revert AlreadyRegistered();

        issuers[issuer].registered = true;
        issuerList.push(issuer);

        for (uint256 i = 0; i < credentialTypeIds.length; i++) {
            issuers[issuer].trustedFor[credentialTypeIds[i]] = true;
            _ensureTypeRegistered(credentialTypeIds[i]);
        }

        emit IssuerRegistered(issuer, credentialTypeIds);
    }

    /// @inheritdoc ISovraIssuerRegistry
    function addCredentialTypes(
        address issuer,
        bytes32[] calldata credentialTypeIds
    ) external onlyRole(ISSUER_MANAGER_ROLE) {
        if (!issuers[issuer].registered) revert IssuerNotRegistered();

        for (uint256 i = 0; i < credentialTypeIds.length; i++) {
            issuers[issuer].trustedFor[credentialTypeIds[i]] = true;
            _ensureTypeRegistered(credentialTypeIds[i]);
        }

        emit IssuerTypesAdded(issuer, credentialTypeIds);
    }

    /// @inheritdoc ISovraIssuerRegistry
    function removeCredentialTypes(
        address issuer,
        bytes32[] calldata credentialTypeIds
    ) external onlyRole(ISSUER_MANAGER_ROLE) {
        if (!issuers[issuer].registered) revert IssuerNotRegistered();

        for (uint256 i = 0; i < credentialTypeIds.length; i++) {
            issuers[issuer].trustedFor[credentialTypeIds[i]] = false;
        }

        emit IssuerTypesRemoved(issuer, credentialTypeIds);
    }

    /// @inheritdoc ISovraIssuerRegistry
    function removeIssuer(address issuer) external onlyRole(ISSUER_MANAGER_ROLE) {
        if (!issuers[issuer].registered) revert IssuerNotRegistered();

        issuers[issuer].registered = false;

        // Remove from issuerList (swap-and-pop)
        for (uint256 i = 0; i < issuerList.length; i++) {
            if (issuerList[i] == issuer) {
                issuerList[i] = issuerList[issuerList.length - 1];
                issuerList.pop();
                break;
            }
        }

        emit IssuerRemoved(issuer);
    }

    // ─── Queries ────────────────────────────────────────

    /// @inheritdoc ISovraIssuerRegistry
    function isTrusted(
        address issuer,
        bytes32 credentialTypeId
    ) external view returns (bool) {
        return issuers[issuer].registered && issuers[issuer].trustedFor[credentialTypeId];
    }

    /// @inheritdoc ISovraIssuerRegistry
    function isRegistered(address issuer) external view returns (bool) {
        return issuers[issuer].registered;
    }

    // ─── Internal ───────────────────────────────────────

    /// @dev Registers a credential type hash if not already known.
    function _ensureTypeRegistered(bytes32 credentialTypeId) internal {
        if (!knownType[credentialTypeId]) {
            knownType[credentialTypeId] = true;
            credentialTypes.push(credentialTypeId);
        }
    }
}
