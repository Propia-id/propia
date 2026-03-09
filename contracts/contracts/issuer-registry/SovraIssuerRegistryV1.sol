// SPDX-License-Identifier: MIT
pragma solidity 0.8.31;

import {ISovraIssuerRegistry} from "./ISovraIssuerRegistry.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/// @title SovraIssuerRegistryV1 - UUPS-upgradeable issuer trust registry
/// @notice Stores which issuers are trusted for which credential types.
///         Admin (owner) manages issuers; verifiers query via isTrusted().
contract SovraIssuerRegistryV1 is ISovraIssuerRegistry, Ownable2StepUpgradeable, UUPSUpgradeable {
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

    /// @notice Initialize the registry with an owner. Called once via proxy.
    /// @param _owner The initial owner address
    function initialize(address _owner) external initializer {
        __Ownable_init(_owner);
        __UUPSUpgradeable_init();
    }

    // ─── UUPS ───────────────────────────────────────────

    /// @dev Restricts upgrades to the owner.
    function _authorizeUpgrade(address) internal override onlyOwner {}

    // ─── Issuer Management ──────────────────────────────

    /// @inheritdoc ISovraIssuerRegistry
    function registerIssuer(
        address issuer,
        bytes32[] calldata credentialTypeIds
    ) external onlyOwner {
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
    ) external onlyOwner {
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
    ) external onlyOwner {
        if (!issuers[issuer].registered) revert IssuerNotRegistered();

        for (uint256 i = 0; i < credentialTypeIds.length; i++) {
            issuers[issuer].trustedFor[credentialTypeIds[i]] = false;
        }

        emit IssuerTypesRemoved(issuer, credentialTypeIds);
    }

    /// @inheritdoc ISovraIssuerRegistry
    function removeIssuer(address issuer) external onlyOwner {
        if (!issuers[issuer].registered) revert IssuerNotRegistered();

        issuers[issuer].registered = false;

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
