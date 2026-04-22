// SPDX-License-Identifier: MIT
pragma solidity 0.8.31;

/// @title ISovraRevocationRegistry - Interface for the Sovra Revocation Registry
/// @notice Manages per-issuer credential status bitmaps following W3C Bitstring Status List v1.0.
///         Each credential is assigned an index in a bitmap; flipping a bit changes its status
///         (revoked or suspended). Verifiers read the full bitmap for herd-privacy.
interface ISovraRevocationRegistry {
    // ─── Errors ──────────────────────────────────────────

    /// @notice Thrown when operating on an issuer that is not registered in the Issuer Registry.
    error IssuerNotRegistered();

    /// @notice Thrown when writing to a bitmap that has not been initialized.
    error BitmapNotInitialized();

    /// @notice Thrown when attempting to initialize an already-initialized bitmap.
    error BitmapAlreadyInitialized();

    /// @notice Thrown when attempting to clear a bit on a revocation bitmap (revocation is permanent).
    error CannotUnrevoke();

    /// @notice Thrown when a purpose value is not REVOCATION or SUSPENSION.
    error InvalidPurpose();

    // ─── Events ──────────────────────────────────────────

    /// @notice Emitted when a bitmap is initialized for an issuer and purpose.
    /// @param issuer The issuer address
    /// @param purpose 0 = revocation, 1 = suspension
    event BitmapInitialized(address indexed issuer, uint8 indexed purpose);

    /// @notice Emitted when a credential's status bit is changed.
    /// @param issuer The issuer address
    /// @param purpose 0 = revocation, 1 = suspension
    /// @param index The credential index in the bitmap
    /// @param value The new bit value (true = revoked/suspended)
    event StatusChanged(address indexed issuer, uint8 indexed purpose, uint256 index, bool value);

    // ─── Functions ───────────────────────────────────────

    /// @notice Initialize a bitmap for an issuer and purpose. Must be called before any status changes.
    /// @param issuer The issuer address (must be registered in the Issuer Registry)
    /// @param purpose 0 = revocation, 1 = suspension
    function initializeBitmap(address issuer, uint8 purpose) external;

    /// @notice Set a credential's status bit to 1 (revoked or suspended).
    /// @param issuer The issuer address
    /// @param purpose 0 = revocation, 1 = suspension
    /// @param index The credential index in the bitmap
    function setStatus(address issuer, uint8 purpose, uint256 index) external;

    /// @notice Clear a credential's status bit to 0 (un-suspend). Reverts for revocation purpose.
    /// @param issuer The issuer address
    /// @param purpose Must be 1 (suspension only)
    /// @param index The credential index in the bitmap
    function clearStatus(address issuer, uint8 purpose, uint256 index) external;

    /// @notice Set multiple credential status bits to 1 in a single transaction.
    /// @param issuer The issuer address
    /// @param purpose 0 = revocation, 1 = suspension
    /// @param indices The credential indices to set
    function batchSetStatus(address issuer, uint8 purpose, uint256[] calldata indices) external;

    /// @notice Check a single credential's status bit.
    /// @param issuer The issuer address
    /// @param purpose 0 = revocation, 1 = suspension
    /// @param index The credential index in the bitmap
    /// @return True if the bit is set (credential is revoked/suspended)
    function getStatus(address issuer, uint8 purpose, uint256 index) external view returns (bool);

    /// @notice Return the full bitmap for an issuer and purpose, padded to at least 512 slots (131,072 bits).
    /// @param issuer The issuer address
    /// @param purpose 0 = revocation, 1 = suspension
    /// @return The bitmap as a uint256 array (at least 512 entries)
    function getBitmap(address issuer, uint8 purpose) external view returns (uint256[] memory);
}
