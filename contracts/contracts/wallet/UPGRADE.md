# Wallet Upgrade Architecture

## Why a Beacon?

Sovra wallets are EOAs that delegate their code to `SovraDispatcher` via EIP-7702. Once a user delegates, the dispatcher address is baked into their EIP-7702 authorization — changing the dispatcher requires the user to re-authorize with their EOA private key. At 1M+ wallets, coordinating individual re-authorizations is infeasible.

The original design used a UUPS pattern where each wallet stored its implementation address in an ERC-1967 slot. Upgrading required each user to sign an `upgrade()` transaction with their passkey — again, infeasible at scale.

A **beacon** solves this by storing the implementation address in a single shared contract. The dispatcher queries the beacon when a wallet has no per-account override. One transaction on the beacon upgrades all wallets instantly.

### Why not a UUPS proxy as the target?

In the EIP-7702 context, the dispatcher uses `delegatecall`, which means any proxy it delegates to would read storage from the **EOA's context**, not its own. A UUPS proxy's stored implementation address would be invisible — it lives in the proxy's own storage, not the EOA's. The beacon avoids this because it's queried via `staticcall` (reads its own storage), not `delegatecall`.

## How It Works

### Resolution Chain

```
EOA call → SovraDispatcher fallback
  1. Read ERC-1967 slot from EOA storage
  2. If set → delegatecall to that address (per-account pin)
  3. If empty → staticcall beacon.implementation() → delegatecall result
```

### Roles

| Role | Who | Can do |
|------|-----|--------|
| **Beacon owner** | Multisig (Ownable2Step) | `scheduleUpgrade()`, `cancelUpgrade()`, `setSecurityCouncil()` |
| **Security council** | Dedicated address | `emergencyUpgrade()` only |
| **Wallet holder** | Passkey signer | `upgrade()` (pin), `resetToBeacon()` (unpin) |

### Upgrade Paths

**Standard upgrade (timelocked, 48h):**

1. Deploy new implementation contract (e.g. `SovraWalletV2`)
2. `beacon.scheduleUpgrade(walletV2Address)` — starts 48h clock
3. Users can monitor `UpgradeScheduled` event and opt-out via `upgrade()` if they disagree
4. After 48h: `beacon.executeUpgrade()` — all unpinned wallets now use V2
5. Cost: **2 transactions**, regardless of user count

**Emergency upgrade (immediate):**

1. Deploy patched implementation
2. `beacon.emergencyUpgrade(patchedAddress)` — called by security council
3. All unpinned wallets are patched immediately
4. Any pending timelocked upgrade is cleared

**Per-account pin (opt-out):**

1. User calls `wallet.upgrade(specificImplAddress, sig)` — writes to ERC-1967 slot
2. Dispatcher reads ERC-1967 first, skips beacon
3. User is now on a fixed version, unaffected by beacon changes

**Per-account unpin (opt back in):**

1. User calls `wallet.resetToBeacon(sig)` — clears ERC-1967 slot
2. Dispatcher falls back to beacon on next call
3. User follows global upgrades again

### Storage Compatibility

New implementations **must** use [ERC-7201](https://eips.ethereum.org/EIPS/eip-7201) namespaced storage for any new fields. This ensures the existing storage layout is never broken, and beacon upgrades work without per-account migration.

If a future upgrade requires restructuring existing storage (rare), use a **lazy migration** pattern:

```solidity
modifier migrateIfNeeded() {
    if (_storageVersion() < 2) {
        _migrateToV2();  // runs once, on first interaction
    }
    _;
}
```

This way, each wallet auto-migrates transparently on its next transaction. No batch job, no coordination.

## Gas Overhead

| Wallet state | Extra cost per call |
|-------------|-------------------|
| Pinned (ERC-1967 set) | 0 — identical to old design |
| Unpinned (beacon lookup) | ~2,600 gas (cold `staticcall`) to ~100 gas (warm) |

At L2 gas prices, the beacon lookup is negligible.

## Security Model

| Threat | Mitigation |
|--------|-----------|
| Malicious beacon upgrade | 48h timelock — users can opt-out before activation |
| Beacon owner key compromised | Ownable2Step (2-tx transfer), owner should be multisig |
| Council key compromised | Council can only upgrade to valid contracts (code check), owner can replace council |
| User disagrees with upgrade | Pin via `upgrade()` — beacon cannot override ERC-1967 slot |

## Deployment

The deploy script (`scripts/deploy.ts`) deploys in order:

1. `SovraWalletV1` — implementation
2. `SovraBeacon` — with implementation address, owner, and security council
3. `SovraDispatcher` — with beacon address
4. `SovraDIDRegistryV1` — implementation + ERC1967Proxy (UUPS)
5. `SovraIssuerRegistryV1` — implementation + ERC1967Proxy (UUPS)

Both registries use UUPS upgradeability with `AccessControlUpgradeable` (issuer registry) or `Ownable2StepUpgradeable` (DID registry). The initial deployer receives all roles/ownership.

After deployment:
- Transfer beacon ownership to a multisig and set the security council via `setSecurityCouncil()`
- On the issuer registry, grant `ISSUER_MANAGER_ROLE` and `UPGRADER_ROLE` to the appropriate addresses, then revoke them from the deployer if it should not retain them
