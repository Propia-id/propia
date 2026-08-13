// SPDX-License-Identifier: MIT
pragma solidity 0.8.31;

import {ISignatureRegistry} from "./ISignatureRegistry.sol";
import {IKeyRegistry, IAuthorizationRegistry} from "./IExternalRegistries.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/// @title Timestamps P-256 signatures made by registered issuers.
/// @notice Stores nothing about what was signed: only the digest, so the content
/// stays off-chain. A record proves the signature existed at a block time and
/// cannot be erased.
contract SignatureRegistryV1 is ISignatureRegistry, AccessControlUpgradeable, UUPSUpgradeable {
    /// RIP-7212 P-256 verification precompile.
    address internal constant P256_VERIFIER = address(0x0100);

    /// Half the curve order. Above it, a signature has an equally valid twin.
    uint256 internal constant P256_N_DIV_2 =
        0x7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8;

    /// Both come from the key registry's encoding: `keyType` is an enum and
    /// `relationships` a bitmask, so assertion is a bit and not a value.
    uint8 internal constant KEY_TYPE_P256 = 0;
    uint8 internal constant RELATIONSHIP_ASSERTION = 2;

    bytes32 public constant RECORDER_ROLE = keccak256("RECORDER_ROLE");

    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    IKeyRegistry public keyRegistry;

    IAuthorizationRegistry public authorizationRegistry;

    /// Keyed by signer and digest: the same digest from two issuers is two records.
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

    /// @notice Verifies the signature here, on-chain, before storing it. The role
    /// only says who may write and pay: it cannot make an invalid signature pass.
    /// Checks run cheapest first, so a bad call fails before touching storage or
    /// another contract.
    function record(address signer, bytes32 typeId, bytes32 digest, bytes32 r, bytes32 s)
        external
        onlyRole(RECORDER_ROLE)
    {
        if (digest == bytes32(0)) revert EmptyDigest();
        if (records[signer][digest].recordedAt != 0) revert AlreadyRecorded();
        if (!authorizationRegistry.isTrusted(signer, typeId)) revert NotAuthorized();

        (bytes32 pubKeyX, bytes32 pubKeyY) = _signerKey(signer);
        if (!_verifyP256(digest, r, s, pubKeyX, pubKeyY)) revert InvalidSignature();

        uint64 recordedAt = uint64(block.timestamp);
        // `r` and `s` are never read back by this contract. They are kept so a
        // verifier can read the signature from the chain without the document.
        records[signer][digest] = Record({r: r, s: s, recordedAt: recordedAt});

        emit SignatureRecorded(signer, digest, recordedAt);
    }

    function getRecord(address signer, bytes32 digest) external view returns (Record memory) {
        return records[signer][digest];
    }

    function isRecorded(address signer, bytes32 digest) external view returns (bool) {
        return records[signer][digest].recordedAt != 0;
    }

    /// The signer's P-256 assertion key, straight from the key registry. Reverts
    /// when there is none, so an issuer must be registered before recording.
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

    function _verifyP256(bytes32 hash, bytes32 r, bytes32 s, bytes32 pubKeyX, bytes32 pubKeyY)
        internal
        view
        returns (bool)
    {
        // Only the canonical half is accepted, so one signature has one encoding.
        if (uint256(s) > P256_N_DIV_2) revert SignatureMalleability();

        (bool success, bytes memory result) = P256_VERIFIER.staticcall(
            abi.encode(hash, r, s, pubKeyX, pubKeyY)
        );

        // On a chain without the precompile the staticcall succeeds with empty
        // returndata, so the length check is what makes this fail closed: nothing
        // can be recorded there, rather than everything being accepted.
        return success && result.length >= 32 && abi.decode(result, (uint256)) == 1;
    }
}
