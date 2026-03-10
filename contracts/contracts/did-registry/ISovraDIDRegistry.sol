// SPDX-License-Identifier: MIT
pragma solidity 0.8.31;

/// @title ISovraDIDRegistry - Interface for the Sovra DID Registry
/// @notice Stores on-chain DID documents (keys + service endpoints) for issuers and verifiers.
///         Admin (owner) manages DIDs on behalf of identities; anyone can resolve.
interface ISovraDIDRegistry {
    // ─── Types ──────────────────────────────────────────

    struct VerificationMethod {
        bytes32 id;             // fragment identifier, e.g., keccak256("key-assert")
        uint8   keyType;        // 0 = P256, 1 = secp256k1, 2 = Ed25519
        bytes32 pubKeyX;        // public key X coordinate
        bytes32 pubKeyY;        // public key Y coordinate
        uint8   relationships;  // bitmask: bit0=auth, bit1=assertion, bit2=invocation, bit3=delegation, bit4=keyAgreement
    }

    struct ServiceEndpoint {
        bytes32 id;             // fragment identifier, e.g., keccak256("oid4vci")
        bytes32 serviceType;    // keccak256 of type string, e.g., keccak256("OpenID4VCIIssuer")
        string  endpoint;       // URL string
    }

    // ─── Errors ─────────────────────────────────────────

    /// @notice Thrown when creating a DID that already exists.
    error DIDAlreadyExists();

    /// @notice Thrown when operating on a DID that does not exist.
    error DIDNotFound();

    /// @notice Thrown when operating on a deactivated DID.
    error DIDIsDeactivated();

    /// @notice Thrown when creating a DID with no verification methods.
    error NoVerificationMethods();

    // ─── Events ─────────────────────────────────────────

    event DIDCreated(address indexed identity, uint32 versionId);
    event DIDUpdated(address indexed identity, uint32 versionId);
    event DIDDeactivated(address indexed identity, uint32 versionId);

    // ─── Functions ──────────────────────────────────────

    /// @notice Create a DID for `identity` with initial keys and service endpoints.
    /// @param identity The address whose DID is being created
    /// @param methods The initial verification methods
    /// @param services The initial service endpoints
    function create(
        address identity,
        VerificationMethod[] calldata methods,
        ServiceEndpoint[] calldata services
    ) external;

    /// @notice Full replacement of keys and services for `identity`.
    /// @param identity The address whose DID is being updated
    /// @param methods The new verification methods (replaces all existing)
    /// @param services The new service endpoints (replaces all existing)
    function update(
        address identity,
        VerificationMethod[] calldata methods,
        ServiceEndpoint[] calldata services
    ) external;

    /// @notice Permanently deactivate the DID for `identity`.
    /// @param identity The address whose DID is being deactivated
    function deactivate(address identity) external;

    /// @notice Resolve the DID document for `identity`.
    /// @param identity The address to resolve
    /// @return methods The verification methods
    /// @return services The service endpoints
    /// @return created The creation timestamp
    /// @return updated The last update timestamp
    /// @return versionId The current version
    /// @return deactivated Whether the DID is deactivated
    function resolve(address identity) external view returns (
        VerificationMethod[] memory methods,
        ServiceEndpoint[] memory services,
        uint64 created,
        uint64 updated,
        uint32 versionId,
        bool deactivated
    );
}
