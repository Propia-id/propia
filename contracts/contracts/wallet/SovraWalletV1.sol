// SPDX-License-Identifier: MIT
pragma solidity 0.8.31;

import {ISovraWallet} from "./ISovraWallet.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";

/// @title SovraWalletV1 - Implementation for EIP-7702 delegated holder wallets
/// @notice All wallet logic: passkey-only P256 signature validation, arbitrary call execution,
///         DID state management, cooperative key rotation, permanent deactivation,
///         time-locked single-key recovery, and UUPS upgradeability.
///         The recovery key is stored on-chain but only used for time-locked recovery.
///         Runs in the EOA's storage context via the SovraDispatcher proxy.
/// @dev P256 verification uses the EIP-7212 precompile at address(0x0100), which exists
///      natively on the ethrex L2. For local Hardhat tests, a Solidity mock is etched there.
///      Future V2+ implementations MUST use ERC-7201 namespaced storage for new fields.
contract SovraWalletV1 is ISovraWallet, ReentrancyGuardUpgradeable, EIP712Upgradeable {
    // ─── ERC-1967 ────────────────────────────────────────

    /// @dev ERC-1967 implementation storage slot, written by upgrade().
    bytes32 internal constant IMPL_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    // ─── P256 Precompile ─────────────────────────────────

    /// @dev EIP-7212 P256 signature verification precompile address.
    address internal constant P256_VERIFIER = address(0x0100);

    /// @dev Half of the P-256 curve order, for low-s signature enforcement.
    /// P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    uint256 internal constant P256_N_DIV_2 =
        0x7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8;

    // ─── Keys ────────────────────────────────────────────

    /// @inheritdoc ISovraWallet
    bytes32 public passkeyX;
    /// @inheritdoc ISovraWallet
    bytes32 public passkeyY;
    /// @inheritdoc ISovraWallet
    bytes32 public recoveryKeyX;
    /// @inheritdoc ISovraWallet
    bytes32 public recoveryKeyY;

    // ─── DID Metadata ────────────────────────────────────

    /// @inheritdoc ISovraWallet
    uint64 public didCreated;
    /// @inheritdoc ISovraWallet
    uint64 public didUpdated;
    /// @inheritdoc ISovraWallet
    uint32 public didVersionId;
    /// @inheritdoc ISovraWallet
    bool public didDeactivated;

    // ─── Replay Protection ───────────────────────────────

    /// @inheritdoc ISovraWallet
    uint256 public nonce;

    // ─── Recovery ────────────────────────────────────────

    /// @inheritdoc ISovraWallet
    RecoveryRequest public pendingRecovery;
    /// @inheritdoc ISovraWallet
    uint64 public constant RECOVERY_DELAY = 7 days;

    // ─── Constructor ─────────────────────────────────────

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // ─── Internal Helpers ────────────────────────────────

    /// @dev Builds the final EIP-712 message hash that the passkey signs.
    /// @param operationHash The keccak256 hash of the operation-specific parameters
    /// @param _nonce The current sequential nonce for replay protection
    /// @return The EIP-712 structured message hash with \x19\x01 prefix
    function _buildMessageHash(bytes32 operationHash, uint256 _nonce) internal view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(operationHash, _nonce));
        return _hashTypedDataV4(structHash);
    }

    /// @dev Verifies a single P256 signature via the EIP-7212 precompile at address(0x0100).
    ///      Sends 160 bytes (hash || r || s || x || y) via staticcall; expects uint256(1) on success.
    /// @param hash The 32-byte message hash that was signed
    /// @param r r component of the P256 signature
    /// @param s s component of the P256 signature
    /// @param pubKeyX X coordinate of the signer's P256 public key
    /// @param pubKeyY Y coordinate of the signer's P256 public key
    /// @return True if the signature is valid
    function _verifyP256(
        bytes32 hash,
        bytes32 r, bytes32 s,
        bytes32 pubKeyX, bytes32 pubKeyY
    ) internal view returns (bool) {
        if (uint256(s) > P256_N_DIV_2) revert SignatureMalleability();
        (bool success, bytes memory result) = P256_VERIFIER.staticcall(
            abi.encode(hash, r, s, pubKeyX, pubKeyY)
        );
        return success && result.length >= 32 && abi.decode(result, (uint256)) == 1;
    }

    /// @dev Verifies the passkey signature against the stored public key.
    /// @param msgHash The EIP-712 message hash to verify against
    /// @param passkeyR r component of the passkey's P256 signature
    /// @param passkeyS s component of the passkey's P256 signature
    function _verifyPasskey(
        bytes32 msgHash,
        bytes32 passkeyR, bytes32 passkeyS
    ) internal view {
        if (!_verifyP256(msgHash, passkeyR, passkeyS, passkeyX, passkeyY)) {
            revert InvalidPasskeySig();
        }
    }

    /// @dev Reverts if the given key is the zero point (0,0).
    function _rejectZeroKey(bytes32 x, bytes32 y) internal pure {
        if (x == 0 && y == 0) revert ZeroKey();
    }

    // ─── Functions ───────────────────────────────────────

    /// @inheritdoc ISovraWallet
    function initialize(
        bytes32 _passkeyX, bytes32 _passkeyY,
        bytes32 _recoveryKeyX, bytes32 _recoveryKeyY,
        bytes32 passkeyR, bytes32 passkeyS
    ) external initializer {
        if (didCreated != 0) revert AlreadyInitialized();

        __ReentrancyGuard_init();
        __EIP712_init("SovraWallet", "1");

        _rejectZeroKey(_passkeyX, _passkeyY);
        _rejectZeroKey(_recoveryKeyX, _recoveryKeyY);

        bytes32 initHash = keccak256(abi.encode(
            address(this), block.chainid, _passkeyX, _passkeyY, _recoveryKeyX, _recoveryKeyY
        ));

        if (!_verifyP256(initHash, passkeyR, passkeyS, _passkeyX, _passkeyY)) {
            revert InvalidPasskeySig();
        }

        passkeyX = _passkeyX;
        passkeyY = _passkeyY;
        recoveryKeyX = _recoveryKeyX;
        recoveryKeyY = _recoveryKeyY;

        didCreated = uint64(block.timestamp);
        didUpdated = uint64(block.timestamp);
        didVersionId = 1;

        emit DIDCreated(address(this), 1);
    }

    /// @inheritdoc ISovraWallet
    function execute(
        address target,
        uint256 value,
        bytes calldata data,
        bytes32 passkeyR, bytes32 passkeyS
    ) external nonReentrant returns (bytes memory) {
        if (didDeactivated) revert DIDIsDeactivated();

        bytes32 opHash = keccak256(abi.encode(target, value, data));
        bytes32 msgHash = _buildMessageHash(opHash, nonce);

        _verifyPasskey(msgHash, passkeyR, passkeyS);

        nonce++;

        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) revert CallFailed(result);

        emit Executed(address(this), target, value, nonce - 1);
        return result;
    }

    /// @inheritdoc ISovraWallet
    function rotatePasskey(
        bytes32 newX, bytes32 newY,
        bytes32 passkeyR, bytes32 passkeyS
    ) external {
        if (didDeactivated) revert DIDIsDeactivated();
        _rejectZeroKey(newX, newY);

        bytes32 opHash = keccak256(abi.encode(bytes4(keccak256("rotatePasskey")), newX, newY));
        bytes32 msgHash = _buildMessageHash(opHash, nonce);

        _verifyPasskey(msgHash, passkeyR, passkeyS);

        nonce++;
        passkeyX = newX;
        passkeyY = newY;
        didUpdated = uint64(block.timestamp);
        didVersionId++;

        emit DIDUpdated(address(this), didVersionId);
    }

    /// @inheritdoc ISovraWallet
    function rotateRecoveryKey(
        bytes32 newX, bytes32 newY,
        bytes32 passkeyR, bytes32 passkeyS
    ) external {
        if (didDeactivated) revert DIDIsDeactivated();
        _rejectZeroKey(newX, newY);

        bytes32 opHash = keccak256(abi.encode(bytes4(keccak256("rotateRecoveryKey")), newX, newY));
        bytes32 msgHash = _buildMessageHash(opHash, nonce);

        _verifyPasskey(msgHash, passkeyR, passkeyS);

        nonce++;
        recoveryKeyX = newX;
        recoveryKeyY = newY;
        didUpdated = uint64(block.timestamp);
        didVersionId++;

        emit DIDUpdated(address(this), didVersionId);
    }

    /// @inheritdoc ISovraWallet
    function deactivate(
        bytes32 passkeyR, bytes32 passkeyS
    ) external {
        if (didDeactivated) revert AlreadyDeactivated();

        bytes32 opHash = keccak256(abi.encode(bytes4(keccak256("deactivate"))));
        bytes32 msgHash = _buildMessageHash(opHash, nonce);

        _verifyPasskey(msgHash, passkeyR, passkeyS);

        nonce++;
        didDeactivated = true;
        didVersionId++;

        emit DIDDeactivated(address(this), didVersionId);
    }

    /// @inheritdoc ISovraWallet
    function upgrade(
        address newImplementation,
        bytes32 passkeyR, bytes32 passkeyS
    ) external {
        if (didDeactivated) revert DIDIsDeactivated();
        if (newImplementation == address(0)) revert InvalidImplementation();
        if (newImplementation.code.length == 0) revert NotAContract();

        bytes32 opHash = keccak256(abi.encode(bytes4(keccak256("upgrade")), newImplementation));
        bytes32 msgHash = _buildMessageHash(opHash, nonce);

        _verifyPasskey(msgHash, passkeyR, passkeyS);

        nonce++;

        assembly {
            sstore(IMPL_SLOT, newImplementation)
        }

        emit Upgraded(address(this), newImplementation);
    }

    /// @inheritdoc ISovraWallet
    function resetToBeacon(
        bytes32 passkeyR, bytes32 passkeyS
    ) external {
        if (didDeactivated) revert DIDIsDeactivated();

        bytes32 opHash = keccak256(abi.encode(bytes4(keccak256("resetToBeacon"))));
        bytes32 msgHash = _buildMessageHash(opHash, nonce);

        _verifyPasskey(msgHash, passkeyR, passkeyS);

        nonce++;

        assembly {
            sstore(IMPL_SLOT, 0)
        }

        emit ResetToBeacon(address(this));
    }

    /// @inheritdoc ISovraWallet
    function initiateRecovery(
        bytes32 newKeyX, bytes32 newKeyY,
        uint8 keyToReplace,
        bytes32 sigR, bytes32 sigS
    ) external {
        if (didDeactivated) revert DIDIsDeactivated();
        if (pendingRecovery.active) revert RecoveryAlreadyPending();
        if (keyToReplace > 1) revert InvalidKeyIndex();
        _rejectZeroKey(newKeyX, newKeyY);

        bytes32 opHash = keccak256(abi.encode(
            bytes4(keccak256("initiateRecovery")),
            newKeyX, newKeyY, keyToReplace
        ));
        bytes32 msgHash = _buildMessageHash(opHash, nonce);

        // Surviving key (NOT being replaced) signs
        if (keyToReplace == 0) {
            if (!_verifyP256(msgHash, sigR, sigS, recoveryKeyX, recoveryKeyY)) revert InvalidSig();
        } else {
            if (!_verifyP256(msgHash, sigR, sigS, passkeyX, passkeyY)) revert InvalidSig();
        }

        nonce++;
        pendingRecovery = RecoveryRequest({
            newKeyX: newKeyX,
            newKeyY: newKeyY,
            keyToReplace: keyToReplace,
            initiatedAt: uint64(block.timestamp),
            active: true
        });

        emit RecoveryInitiated(address(this), keyToReplace, newKeyX, newKeyY);
    }

    /// @inheritdoc ISovraWallet
    function cancelRecovery(
        bytes32 sigR, bytes32 sigS,
        uint8 signerKey
    ) external {
        if (!pendingRecovery.active) revert NoRecoveryPending();
        if (signerKey > 1) revert InvalidKeyIndex();

        bytes32 opHash = keccak256(abi.encode(bytes4(keccak256("cancelRecovery"))));
        bytes32 msgHash = _buildMessageHash(opHash, nonce);

        if (signerKey == 0) {
            if (!_verifyP256(msgHash, sigR, sigS, passkeyX, passkeyY)) revert InvalidSig();
        } else {
            if (!_verifyP256(msgHash, sigR, sigS, recoveryKeyX, recoveryKeyY)) revert InvalidSig();
        }

        nonce++;
        delete pendingRecovery;

        emit RecoveryCancelled(address(this));
    }

    /// @inheritdoc ISovraWallet
    function finalizeRecovery(
        bytes32 sigR, bytes32 sigS
    ) external {
        RecoveryRequest memory req = pendingRecovery;
        if (!req.active) revert NoRecoveryPending();
        if (block.timestamp < req.initiatedAt + RECOVERY_DELAY) revert RecoveryDelayNotElapsed();

        bytes32 opHash = keccak256(abi.encode(bytes4(keccak256("finalizeRecovery"))));
        bytes32 msgHash = _buildMessageHash(opHash, nonce);

        // Surviving key signs finalization
        if (req.keyToReplace == 0) {
            if (!_verifyP256(msgHash, sigR, sigS, recoveryKeyX, recoveryKeyY)) revert InvalidSig();
        } else {
            if (!_verifyP256(msgHash, sigR, sigS, passkeyX, passkeyY)) revert InvalidSig();
        }

        nonce++;

        if (req.keyToReplace == 0) {
            passkeyX = req.newKeyX;
            passkeyY = req.newKeyY;
        } else {
            recoveryKeyX = req.newKeyX;
            recoveryKeyY = req.newKeyY;
        }

        didUpdated = uint64(block.timestamp);
        didVersionId++;
        delete pendingRecovery;

        emit DIDUpdated(address(this), didVersionId);
        emit RecoveryFinalized(address(this), req.keyToReplace);
    }
}
