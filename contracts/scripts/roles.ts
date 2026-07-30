import { ethers } from "ethers";
import {
  DEFAULT_ADMIN_ROLE,
  NetworkRoleConfig,
  REGISTRY_NAMES,
  REGISTRY_ROLES,
  RegistryName,
  roleId,
} from "./chain-config";

/// Applies chain/config.json to deployed registries: grants the configured
/// roles from the deployer (which holds DEFAULT_ADMIN_ROLE from initialize),
/// then optionally renounces the deployer's own bootstrap roles.

// ─── Types ───────────────────────────────────────────

/// Structural view of the AccessControl surface used here — keeps this module
/// independent of typechain and of the hardhat runtime.
export interface CallOverrides {
  from: string;
}

export interface AccessControlReader {
  hasRole(role: string, account: string, overrides: CallOverrides): Promise<boolean>;
}

export interface AccessControlWriter {
  grantRole(role: string, account: string): Promise<{ wait(): Promise<unknown> }>;
  renounceRole(role: string, callerConfirmation: string): Promise<{ wait(): Promise<unknown> }>;
}

/// Reads and writes are separate instances, and every read is sent as the zero
/// address. Both halves are needed:
///
///   - ethrex executes eth_call as a transaction whose nonce must match the
///     sender's, with nonce 0 in the envelope, so a read as the deployer fails
///     with "Nonce mismatch: expected N, got 0" as soon as that key has sent
///     anything — which it always has by the time roles are granted.
///   - hardhat fills in the first configured account as `from` on any eth_call
///     that omits one (SenderProvider, internal/core/providers/accounts), so
///     leaving it unset is not enough; it has to be set explicitly.
///   - ethers rejects a `from` that differs from the signer's address, so the
///     instance carrying that override must be provider-connected.
///
/// The zero address has nonce 0 on every chain, and msg.sender is irrelevant to
/// hasRole.
export interface RegistryHandle {
  read: AccessControlReader;
  write: AccessControlWriter;
}

export type Registries = Record<RegistryName, RegistryHandle>;

const READ_AS_NOBODY: CallOverrides = { from: ethers.ZeroAddress };

export interface RoleGrant {
  contract: RegistryName;
  role: string;
  account: string;
  /// True when the account already held the role, so no transaction was sent.
  alreadyHeld: boolean;
}

export interface RoleRenounce {
  contract: RegistryName;
  role: string;
}

type Logger = (message: string) => void;

const noop: Logger = () => {};

// ─── Apply ───────────────────────────────────────────

export interface AppliedRoles {
  granted: RoleGrant[];
  renounced: RoleRenounce[];
}

/// Grant, optionally renounce, then verify — the whole role step of a
/// deployment. Shared by deploy.ts and apply-roles.ts so a deployment whose
/// role step failed can be finished without redeploying.
export async function applyRoleConfig(
  registries: Registries,
  config: NetworkRoleConfig,
  deployer: string,
  log: Logger = noop
): Promise<AppliedRoles> {
  log("Granting configured roles ...");
  const granted = await grantConfiguredRoles(registries, config, log);

  let renounced: RoleRenounce[] = [];
  if (config.renounceDeployer) {
    log("Renouncing deployer bootstrap roles ...");
    renounced = await renounceDeployerRoles(registries, config, deployer, log);
  }

  await verifyRoles(registries, config, deployer);
  log("  ✓ On-chain roles match chain/config.json");

  return { granted, renounced };
}

// ─── Grant ───────────────────────────────────────────

/// Grants every role listed in the config. Idempotent: an account that already
/// holds a role is skipped, which covers the deployer being listed explicitly.
export async function grantConfiguredRoles(
  registries: Registries,
  config: NetworkRoleConfig,
  log: Logger = noop
): Promise<RoleGrant[]> {
  const grants: RoleGrant[] = [];

  for (const name of REGISTRY_NAMES) {
    for (const role of REGISTRY_ROLES[name]) {
      const id = roleId(role);
      for (const account of config.roles[name][role]) {
        if (await registries[name].read.hasRole(id, account, READ_AS_NOBODY)) {
          log(`  = ${name}.${role} already held by ${account}`);
          grants.push({ contract: name, role, account, alreadyHeld: true });
          continue;
        }
        const tx = await registries[name].write.grantRole(id, account);
        await tx.wait();
        log(`  + ${name}.${role} -> ${account}`);
        grants.push({ contract: name, role, account, alreadyHeld: false });
      }
    }
  }

  return grants;
}

// ─── Renounce ────────────────────────────────────────

/// Drops the deployer's bootstrap roles, DEFAULT_ADMIN_ROLE last so the earlier
/// renounces are still authorised. Irreversible, so before giving up admin on a
/// registry it re-reads on-chain state to confirm a configured non-deployer
/// holder actually has DEFAULT_ADMIN_ROLE.
export async function renounceDeployerRoles(
  registries: Registries,
  config: NetworkRoleConfig,
  deployer: string,
  log: Logger = noop
): Promise<RoleRenounce[]> {
  const address = ethers.getAddress(deployer);
  const renounced: RoleRenounce[] = [];

  // Check every registry before touching any of them, so a missing admin
  // aborts with the deployer's roles still intact.
  for (const name of REGISTRY_NAMES) {
    await assertAdminSurvives(registries[name].read, config, name, address);
  }

  for (const name of REGISTRY_NAMES) {
    const registry = registries[name];
    // DEFAULT_ADMIN_ROLE is listed first in REGISTRY_ROLES; renounce it last.
    const ordered = [
      ...REGISTRY_ROLES[name].filter((role) => role !== DEFAULT_ADMIN_ROLE),
      DEFAULT_ADMIN_ROLE,
    ];

    for (const role of ordered) {
      const id = roleId(role);
      if (!(await registry.read.hasRole(id, address, READ_AS_NOBODY))) continue;

      const tx = await registry.write.renounceRole(id, address);
      await tx.wait();
      log(`  - ${name}.${role} renounced by ${address}`);
      renounced.push({ contract: name, role });
    }
  }

  return renounced;
}

async function assertAdminSurvives(
  registry: AccessControlReader,
  config: NetworkRoleConfig,
  name: RegistryName,
  deployer: string
): Promise<void> {
  const candidates = config.roles[name][DEFAULT_ADMIN_ROLE].filter(
    (holder) => holder !== deployer
  );
  for (const candidate of candidates) {
    if (await registry.hasRole(roleId(DEFAULT_ADMIN_ROLE), candidate, READ_AS_NOBODY)) return;
  }
  throw new Error(
    `refusing to renounce ${name}.${DEFAULT_ADMIN_ROLE}: no configured holder ` +
      `(${candidates.join(", ") || "none"}) has it on-chain — the registry would be ` +
      `left with no admin`
  );
}

// ─── Verification ────────────────────────────────────

/// Re-reads every role from chain and throws on the first mismatch with the
/// config. Cheap (view calls only) and runs after the writes, so a silently
/// dropped transaction cannot be reported as a successful deploy.
export async function verifyRoles(
  registries: Registries,
  config: NetworkRoleConfig,
  deployer: string
): Promise<void> {
  const address = ethers.getAddress(deployer);

  for (const name of REGISTRY_NAMES) {
    const registry = registries[name].read;

    for (const role of REGISTRY_ROLES[name]) {
      const id = roleId(role);

      for (const account of config.roles[name][role]) {
        if (!(await registry.hasRole(id, account, READ_AS_NOBODY))) {
          throw new Error(`${name}.${role} is not held by configured holder ${account}`);
        }
      }

      // initialize() grants all three roles to the deployer, so it holds every
      // role here unless renounceDeployer dropped them.
      const deployerHasRole = await registry.hasRole(id, address, READ_AS_NOBODY);

      if (config.renounceDeployer && deployerHasRole) {
        throw new Error(`${name}.${role} is still held by the deployer ${address}`);
      }
      if (!config.renounceDeployer && !deployerHasRole) {
        throw new Error(
          `${name}.${role} is not held by the deployer ${address} but renounceDeployer is false`
        );
      }
    }
  }
}
