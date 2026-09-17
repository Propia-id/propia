# contracts/

Solidity for `did:sovra`: three UUPS registries (DID, issuer, revocation) plus
the EIP-7702 wallet stack (`SovraWalletV1` implementation, `SovraBeacon`,
`SovraDispatcher`). Hardhat, TypeScript scripts.

```
contracts/     Solidity sources (+ contracts/test/ mocks)
scripts/       deploy, apply-roles, verify
test/          Hardhat tests
chain/         config.json — who holds which role per network (see chain/README.md)
deployments/   deploy output, <network>-<chainId>.json — gitignored
```

Everything runs inside the dev shell (`make shell`, or prefix with
`nix develop --command`). Deploys are driven from the repo root by
`make contracts.*` targets or from here with `npx hardhat`.

## Deploy

Networks are declared in `hardhat.config.ts` and are also the keys of
`chain/config.json`: `anvil`, `sovrachain`, `sovrachain-sepolia`.

**1. Fill in the roles.** `chain/config.json` must have an entry for the target
network with every role of every registry listed. There are no defaults: a
missing field, an unknown role or a zero address aborts the deploy before the
first transaction. See [chain/README.md](chain/README.md) for the shape and for
what each role can do.

**2. Set the environment.**

| Variable | Required | Purpose |
| --- | --- | --- |
| `DEPLOYER_PRIVATE_KEY` | always | pays for the deploy and bootstraps the registries; keeps no role afterwards when `renounceDeployer` is true |
| `RPC_URL` | `sovrachain*` | endpoint of the chain being deployed to (`anvil` is fixed at `127.0.0.1:8545`) |
| `EXPLORER_URL`, `EXPLORER_API_KEY`, `CHAIN_ID` | no | when set, the deploy also submits source verification |

Nothing is loaded from a dotenv file — export the variables in the shell you run
the deploy from.

**3. Run it.**

```bash
# local: anvil on :8545 in another shell. This key is anvil account #0,
# which is also the configured role holder for the `anvil` network.
export DEPLOYER_PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
make contracts.deploy

# remote
cd contracts
DEPLOYER_PRIVATE_KEY=0x… RPC_URL=https://… \
  npx hardhat run scripts/deploy.ts --network sovrachain
```

The script prints the role plan (and any concentration-of-power warnings)
before sending anything, deploys the beacon with `beaconOwner` /
`securityCouncil` from the config, deploys the four registries behind UUPS
proxies with the deployer as bootstrap admin, grants every configured role,
renounces the deployer's own roles when `renounceDeployer` is true, then
re-reads all roles from chain and fails if they do not match the config.

**4. Take the addresses** from `deployments/<network>-<chainId>.json`:

```bash
jq -r '.contracts | to_entries[] | "\(.key): \(.value.address)"' \
  deployments/sovrachain-<chainId>.json
```

The backend needs the three proxies — `DID_REGISTRY_ADDRESS`,
`ISSUER_REGISTRY_ADDRESS`, `REVOCATION_REGISTRY_ADDRESS` — and the verifier app
and verification SDK need the same three. `deployments/` is gitignored, so
record them wherever the environment is configured: the
`*_registry_address` keys in `infra/ansible/playbooks/ini/config-<env>.ini` for
a fleet deploy, `frontend/verifier/.env.local` for the verifier.

### Deploying one registry

A network that already has registries from an earlier full run needs a way to
add or replace a single one — running the full deploy again would deploy a
second copy of everything. `hardhat run` rejects custom params (HH305), so this
form is a task rather than a script:

```bash
cd contracts
DEPLOYER_PRIVATE_KEY=0x… RPC_URL=https://… \
DID_REGISTRY_ADDRESS=0x… ISSUER_REGISTRY_ADDRESS=0x… \
REVOCATION_REGISTRY_ADDRESS=0x… \
  npx hardhat deploy --contract SignatureRegistry --network sovrachain
```

`--contract` takes a registry name from `chain/config.json`, with or without
the `V1` suffix; omitting it deploys everything, exactly as the script does. Every *other* registry has to be named through its
`*_REGISTRY_ADDRESS` variable — the same keys as
`infra/ansible/playbooks/ini/config-<env>.ini`, so what is deployed and what is
served cannot diverge. Those addresses are needed twice over: the target's
`initialize` may take one of them, and the role step re-reads all four against
the config.

Before sending anything it checks that each given address has code, and for
`SignatureRegistry` that the DID and issuer registries answer `resolve` and
`isTrusted` respectively — `keyRegistry` and `authorizationRegistry` have no
setter, so a swapped pair would mean redeploying the proxy. It also verifies a
freshly generated P-256 signature against the precompile at `0x100`: without
it, `P256.verifyNative` reverts and the registry could never record anything.
The full deploy runs that same precompile check.

The output goes to `deployments/<network>-<chainId>-<Contract>.json`, named
apart from the full deploy record so neither overwrites the other, and it lists
all four registries so `apply-roles.ts` can finish the role step if it fails.

The wallet implementation, beacon and dispatcher have no selective form; they
are deployed by a full run.

### If the role step fails

The deployment file is written before the first role transaction, so the
addresses survive and the file says `"applied": false`. Finish without
redeploying:

```bash
DEPLOYMENT_FILE=deployments/<network>-<chainId>.json \
DEPLOYER_PRIVATE_KEY=0x… RPC_URL=https://… \
  npx hardhat run scripts/apply-roles.ts --network <network>
```

Idempotent: roles already in place are skipped. Safe to re-run.

### Verifying later

```bash
DEPLOYMENT_FILE=deployments/<network>-<chainId>.json EXPLORER_URL=https://… \
  npx hardhat run scripts/verify.ts --network <network>
```

## Other targets

```bash
make contracts.setup   # npm ci
make contracts.build   # hardhat compile
make contracts.test    # hardhat test
make contracts.lint    # hardhat check
```

Upgrading the wallet implementation is a separate, timelocked flow — see
[contracts/wallet/UPGRADE.md](contracts/wallet/UPGRADE.md). Registry upgrades
go through `UPGRADER_ROLE` and need `.openzeppelin/` (the upgrade manifest)
committed for the target chain.
