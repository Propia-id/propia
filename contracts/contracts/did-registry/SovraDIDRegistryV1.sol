// SPDX-License-Identifier: MIT
pragma solidity 0.8.31;

import {ISovraDIDRegistry} from "./ISovraDIDRegistry.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/// @title SovraDIDRegistryV1 - UUPS-upgradeable on-chain DID document storage
/// @notice Admin (owner) creates and manages DIDs on behalf of identity addresses.
///         Anyone can resolve a DID.
contract SovraDIDRegistryV1 is ISovraDIDRegistry, Ownable2StepUpgradeable, UUPSUpgradeable {
    // ─── Storage ────────────────────────────────────────

    struct DIDRecord {
        VerificationMethod[] methods;
        ServiceEndpoint[]    services;
        uint64  created;
        uint64  updated;
        uint32  versionId;
        bool    deactivated;
    }

    mapping(address => DIDRecord) internal records;

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

    // ─── Create ─────────────────────────────────────────

    /// @inheritdoc ISovraDIDRegistry
    function create(
        address identity,
        VerificationMethod[] calldata methods,
        ServiceEndpoint[] calldata services
    ) external onlyOwner {
        if (records[identity].created != 0) revert DIDAlreadyExists();
        if (methods.length == 0) revert NoVerificationMethods();

        DIDRecord storage record = records[identity];
        _storeMethods(record, methods);
        _storeServices(record, services);
        record.created = uint64(block.timestamp);
        record.updated = uint64(block.timestamp);
        record.versionId = 1;

        emit DIDCreated(identity, 1);
    }

    // ─── Update ─────────────────────────────────────────

    /// @inheritdoc ISovraDIDRegistry
    function update(
        address identity,
        VerificationMethod[] calldata methods,
        ServiceEndpoint[] calldata services
    ) external onlyOwner {
        DIDRecord storage record = records[identity];
        if (record.created == 0) revert DIDNotFound();
        if (record.deactivated) revert DIDIsDeactivated();

        _clearMethods(record);
        _clearServices(record);
        _storeMethods(record, methods);
        _storeServices(record, services);
        record.updated = uint64(block.timestamp);
        record.versionId++;

        emit DIDUpdated(identity, record.versionId);
    }

    // ─── Deactivate ─────────────────────────────────────

    /// @inheritdoc ISovraDIDRegistry
    function deactivate(address identity) external onlyOwner {
        DIDRecord storage record = records[identity];
        if (record.created == 0) revert DIDNotFound();
        if (record.deactivated) revert DIDIsDeactivated();

        record.deactivated = true;
        record.versionId++;

        emit DIDDeactivated(identity, record.versionId);
    }

    // ─── Read ───────────────────────────────────────────

    /// @inheritdoc ISovraDIDRegistry
    function resolve(address identity) external view returns (
        VerificationMethod[] memory methods,
        ServiceEndpoint[] memory services,
        uint64 created,
        uint64 updated,
        uint32 versionId,
        bool deactivated
    ) {
        DIDRecord storage record = records[identity];
        return (
            record.methods,
            record.services,
            record.created,
            record.updated,
            record.versionId,
            record.deactivated
        );
    }

    // ─── Internal ───────────────────────────────────────

    function _storeMethods(DIDRecord storage record, VerificationMethod[] calldata methods) internal {
        for (uint256 i = 0; i < methods.length; i++) {
            record.methods.push(methods[i]);
        }
    }

    function _storeServices(DIDRecord storage record, ServiceEndpoint[] calldata services) internal {
        for (uint256 i = 0; i < services.length; i++) {
            record.services.push(services[i]);
        }
    }

    function _clearMethods(DIDRecord storage record) internal {
        uint256 len = record.methods.length;
        for (uint256 i = 0; i < len; i++) {
            record.methods.pop();
        }
    }

    function _clearServices(DIDRecord storage record) internal {
        uint256 len = record.services.length;
        for (uint256 i = 0; i < len; i++) {
            record.services.pop();
        }
    }
}
