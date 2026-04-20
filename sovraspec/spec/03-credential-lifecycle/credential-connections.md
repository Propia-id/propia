# Credential Connections

## Purpose

Tracks the relationships between issuers and holders. When a credential is issued, a connection is established between the workspace (issuer) and the holder's DID. This allows the issuer to see which holders have received which credentials and maintain a registry of issued credentials with sequential numbering.

## Requirements

### Requirement: Issuer-holder connection tracking

The system SHALL record connections between issuers and holders upon credential issuance, including sequential credential numbering, credential hash for integrity verification, and status list assignment.

#### Scenario: Record a new connection on issuance
- GIVEN a workspace has just issued a credential to a holder
- WHEN the credential issuance is complete
- THEN a connection record is created linking the workspace's tenantId, the holder's DID, the credentialId, the credential hash, the status list assignment (listId and statusIndex), and a sequential credential number

### Requirement: Credential connection querying

The system SHALL support querying connections by holder DID, credential type, and workspace with pagination, providing a complete view of issued credentials.

#### Scenario: View credentials issued to a specific holder
- GIVEN an issuer wants to see all credentials they have issued to a particular holder
- WHEN they query connections filtered by the holder's DID
- THEN the system returns all credentials issued to that holder by this workspace, including credential type, issuance date, current status, and credential number

#### Scenario: List all issued credentials for a workspace
- GIVEN a workspace admin wants to review all credentials they have issued
- WHEN they request the list of issued credentials with pagination
- THEN the system returns a paginated list of all credential connections including holder DID, credential type, status (active/suspended/revoked), issuance date, and sequential number
