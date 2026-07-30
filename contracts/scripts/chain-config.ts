import { ethers } from "ethers";
import * as fs from "fs";
import * as path from "path";

/// Loader and validator for chain/config.json — the explicit role assignment
/// consumed by scripts/deploy.ts. Pure: no network access, no hardhat import.

// ─── Role catalogue ──────────────────────────────────

export const DEFAULT_ADMIN_ROLE = "DEFAULT_ADMIN_ROLE";

/// The roles each registry actually declares. A config that names a role not
/// listed here for a given contract is rejected rather than silently ignored.
export const REGISTRY_ROLES = {
  SovraDIDRegistryV1: [DEFAULT_ADMIN_ROLE, "DID_MANAGER_ROLE", "UPGRADER_ROLE"],
  SovraIssuerRegistryV1: [DEFAULT_ADMIN_ROLE, "ISSUER_MANAGER_ROLE", "UPGRADER_ROLE"],
  SovraRevocationRegistryV1: [DEFAULT_ADMIN_ROLE, "STATUS_MANAGER_ROLE", "UPGRADER_ROLE"],
} as const;

export type RegistryName = keyof typeof REGISTRY_ROLES;

export const REGISTRY_NAMES = Object.keys(REGISTRY_ROLES) as RegistryName[];

/// AccessControl role identifier. DEFAULT_ADMIN_ROLE is bytes32(0) in
/// OpenZeppelin; every other role is keccak256 of its name.
export function roleId(role: string): string {
  return role === DEFAULT_ADMIN_ROLE
    ? ethers.ZeroHash
    : ethers.keccak256(ethers.toUtf8Bytes(role));
}

// ─── Types ───────────────────────────────────────────

export type RegistryRoles = Record<string, string[]>;

export interface NetworkRoleConfig {
  /// Hardhat network name this entry was read for.
  network: string;
  /// Beacon owner: schedules/cancels timelocked wallet upgrades, appoints the council.
  beaconOwner: string;
  /// Beacon security council: emergencyUpgrade(), bypasses the 48h timelock.
  securityCouncil: string;
  /// Whether the deployer drops its bootstrap roles at the end of the deploy.
  renounceDeployer: boolean;
  /// Registry name -> role name -> holder addresses (checksummed, non-empty).
  roles: Record<RegistryName, RegistryRoles>;
}

const ENTRY_KEYS = ["beaconOwner", "securityCouncil", "renounceDeployer", "roles"];

// ─── Parsing ─────────────────────────────────────────

function fail(message: string): never {
  throw new Error(`chain/config.json: ${message}`);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/// Keys starting with `_` are comments and are not validated.
function significantKeys(value: Record<string, unknown>): string[] {
  return Object.keys(value).filter((key) => !key.startsWith("_"));
}

function parseAddress(value: unknown, where: string): string {
  if (typeof value !== "string") fail(`${where} must be a string, got ${typeof value}`);
  if (!ethers.isAddress(value)) fail(`${where} is not a valid address: ${value}`);
  const address = ethers.getAddress(value);
  if (address === ethers.ZeroAddress) {
    fail(`${where} is the zero address — set a real holder before deploying`);
  }
  return address;
}

function parseHolders(value: unknown, where: string): string[] {
  if (!Array.isArray(value)) fail(`${where} must be an array of addresses`);
  if (value.length === 0) {
    fail(`${where} is empty — remove the role or list at least one holder`);
  }

  const holders: string[] = [];
  const seen = new Set<string>();
  value.forEach((entry, index) => {
    const address = parseAddress(entry, `${where}[${index}]`);
    if (seen.has(address)) fail(`${where} lists ${address} more than once`);
    seen.add(address);
    holders.push(address);
  });
  return holders;
}

function parseRegistryRoles(value: unknown, where: string, name: RegistryName): RegistryRoles {
  if (!isPlainObject(value)) fail(`${where} must be an object`);

  const expected = REGISTRY_ROLES[name];
  const present = significantKeys(value);

  for (const role of present) {
    if (!(expected as readonly string[]).includes(role)) {
      fail(`${where}.${role} is not a role on ${name} (expected: ${expected.join(", ")})`);
    }
  }
  for (const role of expected) {
    if (!present.includes(role)) fail(`${where} is missing ${role}`);
  }

  const roles: RegistryRoles = {};
  for (const role of expected) {
    roles[role] = parseHolders(value[role], `${where}.${role}`);
  }
  return roles;
}

/// Validates the parsed JSON and returns the entry for `networkName`.
/// Throws on anything unexpected — there are no defaults and no fallbacks.
export function parseChainConfig(raw: unknown, networkName: string): NetworkRoleConfig {
  if (!isPlainObject(raw)) fail("top-level value must be an object keyed by network name");

  const networks = significantKeys(raw);
  const entry = raw[networkName];
  if (entry === undefined) {
    fail(`no entry for network "${networkName}" (available: ${networks.join(", ") || "none"})`);
  }
  if (!isPlainObject(entry)) fail(`${networkName} must be an object`);

  for (const key of significantKeys(entry)) {
    if (!ENTRY_KEYS.includes(key)) {
      fail(`${networkName}.${key} is not a known setting (expected: ${ENTRY_KEYS.join(", ")})`);
    }
  }
  for (const key of ENTRY_KEYS) {
    if (entry[key] === undefined) fail(`${networkName}.${key} is missing`);
  }

  if (typeof entry.renounceDeployer !== "boolean") {
    fail(`${networkName}.renounceDeployer must be true or false`);
  }

  const rolesValue = entry.roles;
  if (!isPlainObject(rolesValue)) fail(`${networkName}.roles must be an object`);

  const presentRegistries = significantKeys(rolesValue);
  for (const name of presentRegistries) {
    if (!(REGISTRY_NAMES as string[]).includes(name)) {
      fail(
        `${networkName}.roles.${name} is not a role-managed contract ` +
          `(expected: ${REGISTRY_NAMES.join(", ")})`
      );
    }
  }
  for (const name of REGISTRY_NAMES) {
    if (!presentRegistries.includes(name)) fail(`${networkName}.roles is missing ${name}`);
  }

  const roles = {} as Record<RegistryName, RegistryRoles>;
  for (const name of REGISTRY_NAMES) {
    roles[name] = parseRegistryRoles(rolesValue[name], `${networkName}.roles.${name}`, name);
  }

  return {
    network: networkName,
    beaconOwner: parseAddress(entry.beaconOwner, `${networkName}.beaconOwner`),
    securityCouncil: parseAddress(entry.securityCouncil, `${networkName}.securityCouncil`),
    renounceDeployer: entry.renounceDeployer,
    roles,
  };
}

/// Repo-root chain/config.json, resolved from contracts/scripts/.
export function defaultConfigPath(): string {
  return path.join(__dirname, "..", "..", "chain", "config.json");
}

export function loadChainConfig(
  networkName: string,
  filePath: string = defaultConfigPath()
): NetworkRoleConfig {
  if (!fs.existsSync(filePath)) fail(`not found at ${filePath}`);

  let raw: unknown;
  try {
    raw = JSON.parse(fs.readFileSync(filePath, "utf-8"));
  } catch (err) {
    fail(`invalid JSON in ${filePath}: ${(err as Error).message}`);
  }
  return parseChainConfig(raw, networkName);
}

// ─── Handoff checks ──────────────────────────────────

/// Aborts a `renounceDeployer` run whose config still lists the deployer as a
/// holder: the renounce would revoke what the grant just wrote, and for
/// DEFAULT_ADMIN_ROLE / UPGRADER_ROLE that can leave a registry unadministrable.
/// Call before deploying anything, so a bad config costs no gas.
export function assertDeployerHandoff(config: NetworkRoleConfig, deployer: string): void {
  if (!config.renounceDeployer) return;

  const address = ethers.getAddress(deployer);
  for (const name of REGISTRY_NAMES) {
    for (const [role, holders] of Object.entries(config.roles[name])) {
      if (holders.includes(address)) {
        fail(
          `${config.network}.renounceDeployer is true but ${config.network}.roles.${name}.${role} ` +
            `lists the deployer (${address}) — the renounce would remove it again`
        );
      }
    }
  }
}

/// Non-fatal concentration-of-power notes for the deploy log.
export function handoffWarnings(config: NetworkRoleConfig, deployer: string): string[] {
  const address = ethers.getAddress(deployer);
  const warnings: string[] = [];

  if (!config.renounceDeployer) {
    warnings.push(
      `renounceDeployer is false — the deploy key ${address} keeps DEFAULT_ADMIN_ROLE, ` +
        `UPGRADER_ROLE and the manager role on all three registries`
    );
  }
  if (config.beaconOwner === address) {
    warnings.push(`beaconOwner is the deploy key ${address}`);
  }
  if (config.securityCouncil === address) {
    warnings.push(
      `securityCouncil is the deploy key ${address} — emergencyUpgrade() bypasses the ` +
        `beacon's 48h timelock, so the timelock is cosmetic`
    );
  }
  if (config.securityCouncil === config.beaconOwner) {
    warnings.push(
      `securityCouncil equals beaconOwner (${config.beaconOwner}) — one key both schedules ` +
        `upgrades and bypasses the timelock`
    );
  }
  return warnings;
}
