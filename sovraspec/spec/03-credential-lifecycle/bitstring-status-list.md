# BitstringStatusList

## Purpose

Implements the W3C BitstringStatusListCredential specification for publishing credential revocation and suspension status in publicly verifiable lists. Each workspace has one or more status lists, each capable of tracking 131,072 credentials using 2-bit status values. Status lists are signed by the issuer and cached for performance. Verifiers can check credential status without contacting the issuer directly.

## Requirements

### Requirement: Status index allocation and list management

The system SHALL allocate status indices for new credentials using HMAC-based allocation with optimistic concurrency control, supporting 2-bit status values (0x00 active, 0x01 revoked, 0x02 suspended) and automatic creation of new lists when existing ones are full.

#### Scenario: Allocate status index for a new credential
- GIVEN a new credential is being issued for a workspace
- WHEN the system allocates a status index
- THEN an available index is found in an existing non-full status list (or a new list is created), the index is reserved using HMAC-based allocation with optimistic concurrency, and the listId and statusIndex are returned for embedding in the credential's credentialStatus field

#### Scenario: Concurrent status updates with optimistic concurrency
- GIVEN two administrators simultaneously attempt to change the status of different credentials in the same status list
- WHEN both updates are processed
- THEN the system uses version-based optimistic concurrency control, retrying up to 3 times on version conflicts, ensuring both updates are applied without data loss or corruption

### Requirement: Signed status list credential generation and caching

The system SHALL generate signed W3C BitstringStatusListCredentials with gzip-compressed base64-encoded bitstrings, supporting ETag-based HTTP caching with 5-minute TTL and cache invalidation on status changes.

#### Scenario: Generate a BitstringStatusListCredential
- GIVEN a status list exists for a workspace with some credentials in various states
- WHEN a verifier (or any party) requests the status list credential
- THEN the system returns a signed W3C BitstringStatusListCredential containing: the gzip-compressed base64-encoded bitstring, statusPurpose "message", statusSize 2, status messages for active/revoked/suspended, and a JWT signature from the issuer

### Requirement: Status verification by index

The system SHALL allow verification of credential status by reading the 2-bit value at a credential's statusIndex, supporting both HTTP-based and direct database-level verification.

#### Scenario: Verify credential status by index
- GIVEN a verifier needs to check whether a specific credential is active, revoked, or suspended
- WHEN the verifier reads the bitstring at the credential's statusIndex in the specified statusList
- THEN the 2-bit value at that index indicates the credential's current status (0x00 = active, 0x01 = revoked, 0x02 = suspended), and if revoked or suspended, the verification fails with an appropriate error
