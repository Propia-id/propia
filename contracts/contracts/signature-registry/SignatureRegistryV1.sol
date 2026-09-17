// SPDX-License-Identifier: MIT
pragma solidity 0.8.31;

import {ISignatureRegistry} from "./ISignatureRegistry.sol";
import {IKeyRegistry, IAuthorizationRegistry} from "./IExternalRegistries.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";

/// @title Timestamps P-256 signatures made by registered issuers.
/// @notice Records only the digest, never the signed content.
contract SignatureRegistryV1 is ISignatureRegistry, AccessControlUpgradeable, UUPSUpgradeable {
    /// Mirrors the key registry's encoding: `keyType` is an enum, `relationships`
    /// a bitmask.
    uint8 internal constant KEY_TYPE_P256 = 0;
    uint8 internal constant RELATIONSHIP_ASSERTION = 2;

    bytes32 public constant RECORDER_ROLE = keccak256("RECORDER_ROLE");

    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    IKeyRegistry public keyRegistry;

    IAuthorizationRegistry public authorizationRegistry;

    /// Keyed by signer and digest, so one digest from two issuers is two records.
    mapping(address => mapping(bytes32 => Record)) internal records;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address admin, address keyRegistryAddr, address authorizationRegistryAddr)
        external
        initializer
    {
        __AccessControl_init();
        __UUPSUpgradeable_init();
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(RECORDER_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);
        keyRegistry = IKeyRegistry(keyRegistryAddr);
        authorizationRegistry = IAuthorizationRegistry(authorizationRegistryAddr);
    }

    function _authorizeUpgrade(address) internal override onlyRole(UPGRADER_ROLE) {}

    /// @notice Verifies the signature on-chain before storing it. RECORDER_ROLE
    /// governs who may write, not whether a signature is valid.
    function record(address signer, bytes32 typeId, bytes32 digest, bytes32 r, bytes32 s)
        external
        onlyRole(RECORDER_ROLE)
    {
        if (digest == bytes32(0)) revert EmptyDigest();
        if (records[signer][digest].recordedAt != 0) revert AlreadyRecorded();
        if (!authorizationRegistry.isTrusted(signer, typeId)) revert NotAuthorized();

        (bytes32 pubKeyX, bytes32 pubKeyY) = _signerKey(signer);
        if (!P256.verifyNative(digest, r, s, pubKeyX, pubKeyY)) revert InvalidSignature();

        uint64 recordedAt = uint64(block.timestamp);
        // Kept for off-chain verifiers; this contract never reads them back.
        records[signer][digest] = Record({r: r, s: s, recordedAt: recordedAt});

        emit SignatureRecorded(signer, digest, recordedAt);
    }

    function getRecord(address signer, bytes32 digest) external view returns (Record memory) {
        return records[signer][digest];
    }

    function isRecorded(address signer, bytes32 digest) external view returns (bool) {
        return records[signer][digest].recordedAt != 0;
    }

    /// The signer's P-256 assertion key. Reverts when the key registry has none.
    function _signerKey(address signer) internal view returns (bytes32, bytes32) {
        (IKeyRegistry.VerificationMethod[] memory methods,,,,,) = keyRegistry.resolve(signer);

        for (uint256 i = 0; i < methods.length; i++) {
            if (
                methods[i].keyType == KEY_TYPE_P256 &&
                (methods[i].relationships & RELATIONSHIP_ASSERTION) != 0
            ) {
                return (methods[i].pubKeyX, methods[i].pubKeyY);
            }
        }

        revert NoRegisteredKey();
    }
}
