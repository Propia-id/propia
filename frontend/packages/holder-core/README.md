# @sovrahq/holder-core

Platform-agnostic core for a Sovra credential holder/wallet. It bundles the logic
a holder app needs, independent of any specific runtime (React Native, browser, …):

- **Platform interfaces** — `SecureStorage`, `PasskeyProvider`, `CameraScanner` contracts
  the host app implements.
- **API client** — `ApiClient` for issuer/auth-server metadata and token exchange.
- **State stores** — `createCredentialStore`, `createApprovalStore` (Zustand).
- **Credential manager** — `CredentialManager` for parsing/handling SD-JWT VCs.
- **Protocol flows** — `IssuanceProtocol` (OpenID4VCI) and `PresentationProtocol` (OpenID4VP).
- **Crypto utilities** — `keccak256`, `sha256`, P-256 signing, and EIP-712 helpers
  (exported from `@sovrahq/holder-core/utils`).

## Install

```sh
npm install @sovrahq/holder-core
```

## Usage

```ts
import { ApiClient, CredentialManager } from "@sovrahq/holder-core";
import { base64urlEncode } from "@sovrahq/holder-core/utils";
```

The published package ships compiled JavaScript and type declarations from `dist/`.
