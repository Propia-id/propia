# Authorization Server

## Purpose

An integrated OAuth2/OIDC authorization server that handles token issuance for the credential issuance flow. Supports pre-authorized code grants (primary flow for OID4VCI), authorization code grants with PKCE, and Pushed Authorization Requests (PAR). The authorization server issues access tokens that credential endpoints validate before issuing credentials.

## Requirements

### Requirement: Pre-authorized code and token exchange

The system SHALL support pre-authorized code grants with optional txCode validation, issuing access tokens with c_nonce for credential request binding, and anonymous access for pre-authorized code grants.

#### Scenario: Exchange pre-authorized code for access token
- GIVEN a holder has received a credential offer with a pre-authorized code
- WHEN the holder's wallet sends a token request with grant_type `urn:ietf:params:oauth:grant-type:pre-authorized_code` and the pre-authorized code
- THEN the authorization server validates the code, generates an access token with a c_nonce (for proof of possession in the subsequent credential request), and returns the token response

#### Scenario: Pre-authorized code with txCode validation
- GIVEN a credential offer requires a transaction code (PIN) and the holder has received the PIN via email
- WHEN the holder's wallet sends a token request with the pre-authorized code and the txCode
- THEN the authorization server validates both the pre-authorized code and the txCode, and only issues an access token if both are correct

### Requirement: Authorization code grant and PAR

The system SHALL support authorization code grants with PKCE (S256 code challenge method) and Pushed Authorization Requests (PAR) for secure authorization request submission.

#### Scenario: Pushed Authorization Request
- GIVEN a client wants to initiate an authorization flow with a complex request
- WHEN the client POSTs the authorization request parameters to the PAR endpoint
- THEN the authorization server validates the request, stores it, and returns a request_uri that the client can use in the subsequent authorization request, avoiding URL length limitations and improving security

### Requirement: Authorization server metadata discovery

The system SHALL expose authorization server metadata at the well-known endpoint including issuer, token_endpoint, authorization_endpoint, par_endpoint, supported grant types, supported code challenge methods, and JWKS URI.

#### Scenario: Authorization server metadata discovery
- GIVEN a holder's wallet needs to discover the authorization server's capabilities
- WHEN the wallet queries the well-known metadata endpoint
- THEN the server returns its metadata including: issuer, token_endpoint, authorization_endpoint, par_endpoint, supported grant types (authorization_code, pre-authorized_code), supported code challenge methods (S256), and JWKS URI
