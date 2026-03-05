// SPDX-License-Identifier: MIT
pragma solidity 0.8.31;

/// @title ISovraIssuerRegistry - Interface for the Sovra Issuer Registry
/// @notice Manages trusted issuers and their credential type scopes.
///         Verifiers query this contract to determine if an issuer is trusted
///         for a specific credential type.
interface ISovraIssuerRegistry {
    // ─── Errors ──────────────────────────────────────────

    /// @notice Thrown when registering an issuer that is already registered.
    error AlreadyRegistered();

    /// @notice Thrown when operating on an issuer that is not registered.
    error IssuerNotRegistered();

    // ─── Events ──────────────────────────────────────────

    /// @notice Emitted when a new issuer is registered with initial credential types.
    /// @param issuer The address of the registered issuer
    /// @param credentialTypeIds The credential types the issuer is trusted for
    event IssuerRegistered(address indexed issuer, bytes32[] credentialTypeIds);

    /// @notice Emitted when an issuer is removed from the registry.
    /// @param issuer The address of the removed issuer
    event IssuerRemoved(address indexed issuer);

    /// @notice Emitted when credential types are added to an existing issuer.
    /// @param issuer The issuer address
    /// @param credentialTypeIds The added credential types
    event IssuerTypesAdded(address indexed issuer, bytes32[] credentialTypeIds);

    /// @notice Emitted when credential types are removed from an issuer.
    /// @param issuer The issuer address
    /// @param credentialTypeIds The removed credential types
    event IssuerTypesRemoved(address indexed issuer, bytes32[] credentialTypeIds);

    // ─── Functions ───────────────────────────────────────

    /// @notice Register a new issuer as trusted for specific credential types.
    /// @param issuer The address of the issuer to register
    /// @param credentialTypeIds The credential types to trust the issuer for
    function registerIssuer(address issuer, bytes32[] calldata credentialTypeIds) external;

    /// @notice Add credential types to an existing issuer's trust scope.
    /// @param issuer The registered issuer address
    /// @param credentialTypeIds The credential types to add
    function addCredentialTypes(address issuer, bytes32[] calldata credentialTypeIds) external;

    /// @notice Remove credential types from an issuer's trust scope.
    /// @param issuer The registered issuer address
    /// @param credentialTypeIds The credential types to remove
    function removeCredentialTypes(address issuer, bytes32[] calldata credentialTypeIds) external;

    /// @notice Fully remove an issuer from the registry.
    /// @param issuer The issuer address to remove
    function removeIssuer(address issuer) external;

    /// @notice Check if an issuer is trusted for a specific credential type.
    /// @param issuer The issuer address to check
    /// @param credentialTypeId The credential type to check
    /// @return True if the issuer is registered and trusted for the type
    function isTrusted(address issuer, bytes32 credentialTypeId) external view returns (bool);

    /// @notice Check if an issuer is registered in the registry.
    /// @param issuer The issuer address to check
    /// @return True if the issuer is registered
    function isRegistered(address issuer) external view returns (bool);

    // ─── View Functions ──────────────────────────────────

    /// @notice Get a registered issuer address by index.
    /// @param index The index in the issuer list
    /// @return The issuer address at the given index
    function issuerList(uint256 index) external view returns (address);

    /// @notice Get a registered credential type by index.
    /// @param index The index in the credential types list
    /// @return The credential type hash at the given index
    function credentialTypes(uint256 index) external view returns (bytes32);

    /// @notice Check if a credential type hash is known (has been registered).
    /// @param credentialTypeId The credential type hash
    /// @return True if the type has been registered
    function knownType(bytes32 credentialTypeId) external view returns (bool);
}
