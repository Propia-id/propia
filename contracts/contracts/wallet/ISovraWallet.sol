// SPDX-License-Identifier: MIT
pragma solidity 0.8.31;

/// @title ISovraWallet - Interface for the Sovra EIP-7702 holder wallet
/// @notice Defines the full API for wallet initialization, execution, key management,
///         DID lifecycle, time-locked recovery, and UUPS upgradeability.
///         Normal operations require passkey-only P256 signature authorization.
///         The recovery key can only initiate time-locked recovery.
interface ISovraWallet {
    // ─── Structs ─────────────────────────────────────────

    /// @notice Pending recovery request stored on-chain during the 7-day delay window.
    /// @param newKeyX X coordinate of the replacement P256 public key
    /// @param newKeyY Y coordinate of the replacement P256 public key
    /// @param keyToReplace Which key is being replaced: 0 = passkey, 1 = recovery key
    /// @param initiatedAt Timestamp when recovery was initiated (used to enforce delay)
    /// @param active Whether this recovery request is currently pending
    struct RecoveryRequest {
        bytes32 newKeyX;
        bytes32 newKeyY;
        uint8 keyToReplace;
        uint64 initiatedAt;
        bool active;
    }

    // ─── Errors ──────────────────────────────────────────

    /// @notice Thrown when initialize() is called on an already-initialized wallet.
    error AlreadyInitialized();

    /// @notice Thrown when an operation is attempted on a deactivated DID.
    error DIDIsDeactivated();

    /// @notice Thrown when deactivate() is called on an already-deactivated DID.
    error AlreadyDeactivated();

    /// @notice Thrown when the passkey P256 signature fails verification.
    error InvalidPasskeySig();

    /// @notice Thrown when a single-key P256 signature fails verification (recovery ops).
    error InvalidSig();

    /// @notice Thrown when execute()'s inner call to the target address reverts.
    /// @param returnData The revert data from the failed call
    error CallFailed(bytes returnData);

    /// @notice Thrown when a P256 signature has a non-normalized (high) s value.
    error SignatureMalleability();

    /// @notice Thrown when a zero (0,0) key is provided where a valid P256 key is required.
    error ZeroKey();

    /// @notice Thrown when upgrade() receives the zero address as the new implementation.
    error InvalidImplementation();

    /// @notice Thrown when upgrade() receives an address with no deployed code.
    error NotAContract();

    /// @notice Thrown when initiateRecovery() is called while another recovery is pending.
    error RecoveryAlreadyPending();

    /// @notice Thrown when cancelRecovery() or finalizeRecovery() is called with no active request.
    error NoRecoveryPending();

    /// @notice Thrown when initiateRecovery() receives an invalid keyToReplace value (must be 0 or 1).
    error InvalidKeyIndex();

    /// @notice Thrown when finalizeRecovery() is called before the 7-day delay has elapsed.
    error RecoveryDelayNotElapsed();

    // ─── Events ──────────────────────────────────────────

    /// @notice Emitted when initialize() successfully sets up the wallet and creates the DID.
    /// @param identity The wallet (EOA) address that was initialized
    /// @param versionId The initial DID version (always 1)
    event DIDCreated(address indexed identity, uint32 versionId);

    /// @notice Emitted when a key rotation or recovery finalization updates the DID state.
    /// @param identity The wallet (EOA) address whose DID was updated
    /// @param versionId The new DID version after the update
    event DIDUpdated(address indexed identity, uint32 versionId);

    /// @notice Emitted when deactivate() permanently disables the DID.
    /// @param identity The wallet (EOA) address whose DID was deactivated
    /// @param versionId The final DID version at deactivation
    event DIDDeactivated(address indexed identity, uint32 versionId);

    /// @notice Emitted when a recovery process is started by the surviving key.
    /// @param identity The wallet (EOA) address initiating recovery
    /// @param keyToReplace Which key is being replaced: 0 = passkey, 1 = recovery key
    /// @param newKeyX X coordinate of the proposed replacement key
    /// @param newKeyY Y coordinate of the proposed replacement key
    event RecoveryInitiated(address indexed identity, uint8 keyToReplace, bytes32 newKeyX, bytes32 newKeyY);

    /// @notice Emitted when a pending recovery is cancelled by either key.
    /// @param identity The wallet (EOA) address whose recovery was cancelled
    event RecoveryCancelled(address indexed identity);

    /// @notice Emitted when a recovery is finalized after the 7-day delay, replacing the lost key.
    /// @param identity The wallet (EOA) address whose key was replaced
    /// @param keyReplaced Which key was replaced: 0 = passkey, 1 = recovery key
    event RecoveryFinalized(address indexed identity, uint8 keyReplaced);

    /// @notice Emitted on each successful execute() call.
    /// @param identity The wallet (EOA) address that executed the call
    /// @param target The address that was called
    /// @param value The ETH value sent with the call
    /// @param nonce The nonce used for this execution (pre-increment)
    event Executed(address indexed identity, address indexed target, uint256 value, uint256 nonce);

    /// @notice Emitted when the implementation address is changed via upgrade().
    /// @param identity The wallet (EOA) address that was upgraded
    /// @param newImplementation The new implementation contract address
    event Upgraded(address indexed identity, address newImplementation);

    // ─── Functions ───────────────────────────────────────

    /// @notice One-time initialization called atomically with the EIP-7702 delegation.
    ///         The passkey proves possession by signing a hash of (walletAddress, all four key coordinates).
    /// @param _passkeyX X coordinate of the holder's P256 passkey
    /// @param _passkeyY Y coordinate of the holder's P256 passkey
    /// @param _recoveryKeyX X coordinate of the recovery server's P256 key
    /// @param _recoveryKeyY Y coordinate of the recovery server's P256 key
    /// @param passkeyR r component of the passkey's P256 signature over the init hash
    /// @param passkeyS s component of the passkey's P256 signature over the init hash
    function initialize(
        bytes32 _passkeyX, bytes32 _passkeyY,
        bytes32 _recoveryKeyX, bytes32 _recoveryKeyY,
        bytes32 passkeyR, bytes32 passkeyS
    ) external;

    /// @notice Execute an arbitrary call from the wallet. Requires passkey P256 signature.
    ///         The signed message includes target, value, data, and the current nonce under EIP-712.
    /// @param target The address to call
    /// @param value The ETH value to send
    /// @param data The calldata to forward
    /// @param passkeyR r component of the passkey's P256 signature
    /// @param passkeyS s component of the passkey's P256 signature
    /// @return The return data from the target call
    function execute(
        address target,
        uint256 value,
        bytes calldata data,
        bytes32 passkeyR, bytes32 passkeyS
    ) external returns (bytes memory);

    /// @notice Replace the passkey with a new P256 key pair. Requires passkey signature.
    ///         Increments nonce and DID versionId, updates didUpdated timestamp.
    /// @param newX X coordinate of the new passkey
    /// @param newY Y coordinate of the new passkey
    /// @param passkeyR r component of the current passkey's P256 signature
    /// @param passkeyS s component of the current passkey's P256 signature
    function rotatePasskey(
        bytes32 newX, bytes32 newY,
        bytes32 passkeyR, bytes32 passkeyS
    ) external;

    /// @notice Replace the recovery key with a new P256 key pair. Requires passkey signature.
    ///         Increments nonce and DID versionId, updates didUpdated timestamp.
    /// @param newX X coordinate of the new recovery key
    /// @param newY Y coordinate of the new recovery key
    /// @param passkeyR r component of the passkey's P256 signature
    /// @param passkeyS s component of the passkey's P256 signature
    function rotateRecoveryKey(
        bytes32 newX, bytes32 newY,
        bytes32 passkeyR, bytes32 passkeyS
    ) external;

    /// @notice Permanently deactivate the DID. Requires passkey signature. Irreversible.
    ///         After deactivation, all operations except view functions are blocked.
    /// @param passkeyR r component of the passkey's P256 signature
    /// @param passkeyS s component of the passkey's P256 signature
    function deactivate(
        bytes32 passkeyR, bytes32 passkeyS
    ) external;

    /// @notice Change the implementation contract (UUPS upgrade). Requires passkey signature.
    ///         Writes the new address to the ERC-1967 implementation slot. The dispatcher
    ///         will delegatecall the new implementation for all subsequent calls.
    /// @param newImplementation Address of the new implementation contract (must have code)
    /// @param passkeyR r component of the passkey's P256 signature
    /// @param passkeyS s component of the passkey's P256 signature
    function upgrade(
        address newImplementation,
        bytes32 passkeyR, bytes32 passkeyS
    ) external;

    /// @notice Start a time-locked recovery to replace a lost key. Only the surviving key signs.
    ///         The other party has a 7-day window to cancel before finalization.
    /// @param newKeyX X coordinate of the proposed replacement key
    /// @param newKeyY Y coordinate of the proposed replacement key
    /// @param keyToReplace Which key to replace: 0 = passkey, 1 = recovery key
    /// @param sigR r component of the surviving key's P256 signature
    /// @param sigS s component of the surviving key's P256 signature
    function initiateRecovery(
        bytes32 newKeyX, bytes32 newKeyY,
        uint8 keyToReplace,
        bytes32 sigR, bytes32 sigS
    ) external;

    /// @notice Cancel a pending recovery. Either key (passkey or recovery) can cancel at any time.
    /// @param sigR r component of the signer's P256 signature
    /// @param sigS s component of the signer's P256 signature
    /// @param signerKey Which key is signing the cancellation: 0 = passkey, 1 = recovery key
    function cancelRecovery(
        bytes32 sigR, bytes32 sigS,
        uint8 signerKey
    ) external;

    /// @notice Complete recovery after the 7-day delay. The surviving key signs finalization.
    ///         Replaces the lost key with the one specified during initiation.
    /// @param sigR r component of the surviving key's P256 signature
    /// @param sigS s component of the surviving key's P256 signature
    function finalizeRecovery(
        bytes32 sigR, bytes32 sigS
    ) external;

    // ─── View Functions ──────────────────────────────────

    /// @notice X coordinate of the holder's P256 passkey.
    function passkeyX() external view returns (bytes32);

    /// @notice Y coordinate of the holder's P256 passkey.
    function passkeyY() external view returns (bytes32);

    /// @notice X coordinate of the recovery server's P256 key.
    function recoveryKeyX() external view returns (bytes32);

    /// @notice Y coordinate of the recovery server's P256 key.
    function recoveryKeyY() external view returns (bytes32);

    /// @notice Timestamp when the DID was created (set during initialize).
    function didCreated() external view returns (uint64);

    /// @notice Timestamp of the last DID update (key rotation, recovery, or creation).
    function didUpdated() external view returns (uint64);

    /// @notice Monotonically increasing DID version counter, starts at 1.
    function didVersionId() external view returns (uint32);

    /// @notice Whether this DID has been permanently deactivated.
    function didDeactivated() external view returns (bool);

    /// @notice Sequential nonce for EIP-712 replay protection.
    function nonce() external view returns (uint256);

    /// @notice The currently pending recovery request, if any.
    /// @return newKeyX X coordinate of proposed replacement key
    /// @return newKeyY Y coordinate of proposed replacement key
    /// @return keyToReplace 0 = passkey, 1 = recovery key
    /// @return initiatedAt Timestamp when recovery was initiated
    /// @return active Whether this recovery is currently pending
    function pendingRecovery() external view returns (bytes32, bytes32, uint8, uint64, bool);

    /// @notice Time-lock delay for recovery finalization (7 days).
    function RECOVERY_DELAY() external pure returns (uint64);
}
