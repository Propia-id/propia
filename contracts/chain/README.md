# contracts/chain/

`config.json` is the explicit role assignment for a contracts deployment. It is
read by `contracts/scripts/deploy.ts` **before** any transaction is sent, so a
bad or unfilled entry costs no gas.

Keys are the Hardhat network names declared in `contracts/hardhat.config.ts`,
passed as `--network <name>`:

| Network | Chain |
| --- | --- |
| `anvil` | local node, fixed at `127.0.0.1:8545` |
| `sovrachain` | Sovra chain (ethrex L2), `RPC_URL` (default `127.0.0.1:1729`) |
| `sovrachain-sepolia` | Sovra chain testnet, `RPC_URL` |

There are no defaults and no fallbacks: a network with no entry, a missing
field, or a zero address aborts the deploy.

## Shape

```jsonc
{
  "sovrachain": {
    "beaconOwner": "0x…",        // SovraBeacon owner: scheduleUpgrade / cancelUpgrade / setSecurityCouncil
    "securityCouncil": "0x…",    // SovraBeacon.emergencyUpgrade(): bypasses the 48h timelock
    "renounceDeployer": true,    // deployer drops its bootstrap roles at the end of the deploy
    "roles": {
      "SovraDIDRegistryV1":        { "DEFAULT_ADMIN_ROLE": ["0x…"], "DID_MANAGER_ROLE":    ["0x…"], "UPGRADER_ROLE": ["0x…"] },
      "SovraIssuerRegistryV1":     { "DEFAULT_ADMIN_ROLE": ["0x…"], "ISSUER_MANAGER_ROLE": ["0x…"], "UPGRADER_ROLE": ["0x…"] },
      "SovraRevocationRegistryV1": { "DEFAULT_ADMIN_ROLE": ["0x…"], "STATUS_MANAGER_ROLE": ["0x…"], "UPGRADER_ROLE": ["0x…"] }
    }
  }
}
```

Every role of every registry must be listed with at least one holder. Multiple
holders are allowed (e.g. a KMS signer and a legacy admin key both holding
`DID_MANAGER_ROLE`). Keys starting with `_` are comments.

## What each role can do

| Role | Capability |
| --- | --- |
| `DEFAULT_ADMIN_ROLE` | grant and revoke every role on that registry |
| `DID_MANAGER_ROLE` | `create` / `update` / `deactivate` any DID |
| `ISSUER_MANAGER_ROLE` | register and remove issuers, manage credential types |
| `STATUS_MANAGER_ROLE` | revoke and un-revoke credentials |
| `UPGRADER_ROLE` | the only gate on `_authorizeUpgrade` — arbitrary code replacement (UUPS, no ProxyAdmin) |
| `beaconOwner` | schedule/cancel timelocked wallet implementation upgrades, appoint the council |
| `securityCouncil` | replace the wallet implementation immediately, bypassing the timelock |

The manager roles are what the backend relayer needs: the address of
`ADMIN_PRIVATE_KEY`, or the KMS signer address when `ADMIN_PRIVATE_KEY` is unset.

## How the deploy uses it

1. Load and validate the entry for the target network; abort on any problem.
2. Deploy the beacon with `beaconOwner` / `securityCouncil` from the config —
   the deploy key is never the beacon owner unless the config says so.
3. Initialize the three registries with the deployer as bootstrap admin (needed
   to grant anything), then grant every configured role. Already-held roles are
   skipped, so re-runs send no redundant transactions.
4. If `renounceDeployer` is true, renounce the deployer's own roles —
   manager and `UPGRADER_ROLE` first, `DEFAULT_ADMIN_ROLE` last.
5. Re-read all roles from chain and abort if they do not match the config.
6. Record the outcome in `contracts/deployments/<network>-<chainId>.json`.

## If the role step fails

Steps 1–2 write the deployment file before any role transaction, so a failure in
3–5 leaves the addresses recorded with `"applied": false`. Finish it without
redeploying:

```
DEPLOYMENT_FILE=deployments/<network>-<chainId>.json \
  npx hardhat run scripts/apply-roles.ts --network <network>
```

It re-reads the config, applies whatever is missing (already-held roles are
skipped), verifies, and updates the file. Safe to re-run.

`renounceDeployer` is irreversible. It is refused up front if the config also
lists the deployer as a holder, and the renounce itself is refused if no
configured `DEFAULT_ADMIN_ROLE` holder actually has the role on-chain.

## Current entries

All three are filled in. `anvil` puts everything on account #0 of the shared
test mnemonic. Both Sovra chain entries use the same split: the manager roles
go to the backend relayer, `DEFAULT_ADMIN_ROLE` / `UPGRADER_ROLE` /
`beaconOwner` to the admin address, and `renounceDeployer` is true so the
deploy key holds nothing afterwards. `securityCouncil` still equals
`beaconOwner` on both — one key both schedules wallet upgrades and bypasses the
48h timelock, which the deploy warns about; splitting them is a
`setSecurityCouncil` call from the beacon owner, no redeploy.

With `renounceDeployer: false` the deploy key keeps `DEFAULT_ADMIN_ROLE`,
`UPGRADER_ROLE` and the manager role on all three registries — fine locally,
a standing root of trust anywhere else. The deploy warns about that, about a
council that equals the deploy key, and about a council that equals the beacon
owner.
