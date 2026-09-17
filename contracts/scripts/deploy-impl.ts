import { ethers, upgrades, run, network } from "hardhat";
import type { Wallet } from "ethers";
import * as fs from "fs";
import * as path from "path";
import { p256 } from "@noble/curves/p256";
import {
  assertDeployerHandoff,
  handoffWarnings,
  loadChainConfig,
  NetworkRoleConfig,
  REGISTRY_NAMES,
  REGISTRY_ROLES,
  RegistryName,
} from "./chain-config";
import { applyRoleConfig, RoleGrant, RoleRenounce } from "./roles";
import { attachRegistries, toRegistries } from "./registries";

/// Deploys everything, or one registry against registries already on the chain
/// when `contract` is set. scripts/deploy.ts is the first, the `deploy` task the
/// second.

/// RIP-7212 / EIP-7951 P-256 verification precompile, the address OpenZeppelin's
/// P256.verifyNative staticcalls.
const P256_VERIFIER = "0x0000000000000000000000000000000000000100";

/// Reads go out as the zero address, which has nonce 0 on every chain. See
/// RegistryHandle in roles.ts for why leaving `from` unset does not work.
const READ_AS_NOBODY = { from: ethers.ZeroAddress };

/// Where a selective run reads a registry it is not deploying. Names match the
/// keys in infra/ansible/playbooks/ini/config-<env>.ini, which the backend reads.
const ADDRESS_ENV: Record<RegistryName, string> = {
  SovraDIDRegistryV1: "DID_REGISTRY_ADDRESS",
  SovraIssuerRegistryV1: "ISSUER_REGISTRY_ADDRESS",
  SovraRevocationRegistryV1: "REVOCATION_REGISTRY_ADDRESS",
  SignatureRegistryV1: "SIGNATURE_REGISTRY_ADDRESS",
};

/// Structural views, so this module does not depend on typechain being in sync.
interface KeyRegistryProbe {
  resolve(identity: string, overrides: typeof READ_AS_NOBODY): Promise<unknown>;
}

interface AuthorizationRegistryProbe {
  isTrusted(
    account: string,
    typeId: string,
    overrides: typeof READ_AS_NOBODY
  ): Promise<boolean>;
}

/// A registry's address getters, read back after initialize().
type AddressGetters = Record<string, (overrides: typeof READ_AS_NOBODY) => Promise<string>>;

export interface DeployOptions {
  /// A registry in chain/config.json. Undefined deploys everything.
  contract?: string;
}

function fail(message: string): never {
  console.error(`Error: ${message}`);
  process.exit(1);
}

function requireAddress(name: string): string {
  const value = process.env[name];
  if (!value) fail(`${name} environment variable is required`);
  if (!ethers.isAddress(value)) fail(`${name} is not a valid address: ${value}`);
  const address = ethers.getAddress(value);
  if (address === ethers.ZeroAddress) fail(`${name} is the zero address`);
  return address;
}

/// Accepts `SignatureRegistryV1` or `SignatureRegistry`, in any case.
function resolveTarget(name: string): RegistryName {
  const wanted = name.trim().toLowerCase();
  const match = REGISTRY_NAMES.find(
    (registry) =>
      registry.toLowerCase() === wanted ||
      registry.toLowerCase().replace(/v1$/, "") === wanted
  );
  if (!match) {
    fail(
      `--contract ${name} is not a registry in chain/config.json ` +
        `(expected one of: ${REGISTRY_NAMES.join(", ")}). The wallet implementation, ` +
        `beacon and dispatcher can only be deployed by a full run.`
    );
  }
  return match;
}

// ─── Preflight ───────────────────────────────────────
// Runs before the first transaction, so an unusable chain or address costs no gas.

async function assertHasCode(address: string, label: string): Promise<void> {
  if ((await ethers.provider.getCode(address)) === "0x") {
    fail(`${label} ${address} has no code on ${network.name}`);
  }
}

/// keyRegistry and authorizationRegistry have no setter, so a swapped pair means
/// redeploying the proxy. `resolve` answers only on the DID registry and
/// `isTrusted` only on the issuer registry, which discriminates the two.
async function assertRegistryInterfaces(
  didRegistryAddress: string,
  issuerRegistryAddress: string
): Promise<void> {
  const didRegistry = (
    await ethers.getContractAt("SovraDIDRegistryV1", didRegistryAddress)
  ).connect(ethers.provider) as unknown as KeyRegistryProbe;

  try {
    await didRegistry.resolve(ethers.ZeroAddress, READ_AS_NOBODY);
  } catch (err: any) {
    fail(
      `${ADDRESS_ENV.SovraDIDRegistryV1} ${didRegistryAddress} does not answer ` +
        `resolve(address) — it is not a DID registry (${err.shortMessage ?? err.message})`
    );
  }

  const issuerRegistry = (
    await ethers.getContractAt("SovraIssuerRegistryV1", issuerRegistryAddress)
  ).connect(ethers.provider) as unknown as AuthorizationRegistryProbe;

  try {
    await issuerRegistry.isTrusted(ethers.ZeroAddress, ethers.ZeroHash, READ_AS_NOBODY);
  } catch (err: any) {
    fail(
      `${ADDRESS_ENV.SovraIssuerRegistryV1} ${issuerRegistryAddress} does not answer ` +
        `isTrusted(address,bytes32) — it is not an issuer registry ` +
        `(${err.shortMessage ?? err.message})`
    );
  }
}

/// Without the precompile, P256.verifyNative reverts MissingPrecompile and
/// `record` can never succeed. The vector is generated per run, not stored.
async function assertP256Precompile(): Promise<void> {
  const privateKey = p256.utils.randomPrivateKey();
  const publicKey = p256.getPublicKey(privateKey, false); // uncompressed: 04 || x || y
  const digest = ethers.keccak256(ethers.toUtf8Bytes("signature registry precompile probe"));
  const signature = p256.sign(ethers.getBytes(digest), privateKey, { lowS: true });

  const input = ethers.concat([
    digest,
    ethers.toBeHex(signature.r, 32),
    ethers.toBeHex(signature.s, 32),
    publicKey.slice(1, 33),
    publicKey.slice(33, 65),
  ]);

  let result: string;
  try {
    result = await ethers.provider.call({ to: P256_VERIFIER, data: input, ...READ_AS_NOBODY });
  } catch (err: any) {
    fail(
      `the P-256 precompile at ${P256_VERIFIER} could not be called on ${network.name}: ` +
        `${err.shortMessage ?? err.message}`
    );
  }

  if (result !== ethers.zeroPadValue("0x01", 32)) {
    fail(
      `${network.name} has no P-256 precompile at ${P256_VERIFIER}: a valid signature ` +
        `returned ${result === "0x" ? "empty returndata" : result} instead of 1. ` +
        `SignatureRegistryV1 cannot record anything on this chain.`
    );
  }
}

/// An EOA holder with no balance cannot use the role it is about to be given,
/// and under renounceDeployer nothing else can upgrade or re-grant. Not fatal:
/// it may be funded later.
async function warnUnfundedHolders(
  config: NetworkRoleConfig,
  names: readonly RegistryName[]
): Promise<void> {
  const holders = new Set<string>();
  for (const name of names) {
    for (const holder of config.roles[name].DEFAULT_ADMIN_ROLE) holders.add(holder);
    for (const holder of config.roles[name].UPGRADER_ROLE) holders.add(holder);
  }

  for (const holder of holders) {
    const [balance, code] = await Promise.all([
      ethers.provider.getBalance(holder),
      ethers.provider.getCode(holder),
    ]);
    if (balance === 0n && code === "0x") {
      console.warn(
        `⚠ WARNING: ${holder} is configured as DEFAULT_ADMIN_ROLE/UPGRADER_ROLE but is an ` +
          `EOA with a zero balance — it cannot send the transaction that upgrades those ` +
          `contracts or changes their roles until it is funded`
      );
    }
  }
}

// ─── Explorer verification ───────────────────────────

async function verify(address: string, constructorArguments: unknown[] = []) {
  const explorerUrl = process.env.EXPLORER_URL;
  if (!explorerUrl) return;

  console.log(`Verifying ${address} on ${explorerUrl} ...`);
  try {
    await run("verify:verify", {
      address,
      constructorArguments,
    });
    console.log(`  ✓ Verified ${address}`);
  } catch (err: any) {
    if (err.message?.includes("Already Verified")) {
      console.log(`  ✓ Already verified ${address}`);
    } else {
      console.warn(`  ✗ Verification failed for ${address}:`, err.message);
    }
  }
}

// ─── Plan ────────────────────────────────────────────

function printPlan(
  config: NetworkRoleConfig,
  deployer: string,
  names: readonly RegistryName[],
  beacon: boolean
) {
  console.log(`\n=== Role plan (chain/config.json -> ${config.network}) ===`);
  if (beacon) {
    console.log("Beacon owner:              ", config.beaconOwner);
    console.log("Beacon security council:   ", config.securityCouncil);
  }
  for (const name of names) {
    console.log(name + ":");
    for (const role of REGISTRY_ROLES[name]) {
      console.log(`  ${role}: ${config.roles[name][role].join(", ")}`);
    }
  }
  console.log(
    `Deployer bootstrap roles: ${config.renounceDeployer ? "renounced after grants" : "kept"}`
  );
  for (const warning of handoffWarnings(config, deployer)) {
    console.warn(`⚠ WARNING: ${warning}`);
  }
  console.log("");
}

// ─── Output file ─────────────────────────────────────

interface ContractRecord {
  address: string;
  type: string;
  /// Present and true for a contract this run did not deploy, only wired to.
  preexisting?: boolean;
}

interface RoleOutcome {
  granted: RoleGrant[];
  renounced: RoleRenounce[];
  complete: boolean;
}

function deploymentsPath(fileName: string): string {
  const deploymentsDir = path.join(__dirname, "..", "deployments");
  if (!fs.existsSync(deploymentsDir)) {
    fs.mkdirSync(deploymentsDir, { recursive: true });
  }
  return path.join(deploymentsDir, fileName);
}

function writeDeployment(
  outputPath: string,
  body: Record<string, unknown>,
  config: NetworkRoleConfig,
  roles: RoleOutcome
): void {
  const output = {
    ...body,
    roles: {
      configured: config.roles,
      renounceDeployer: config.renounceDeployer,
      granted: roles.granted,
      renounced: roles.renounced,
      applied: roles.complete,
    },
  };
  fs.writeFileSync(outputPath, JSON.stringify(output, null, 2) + "\n");
}

// ─── Full deployment ─────────────────────────────────

async function deployAll(
  deployer: Wallet,
  chainId: bigint,
  roleConfig: NetworkRoleConfig
): Promise<void> {
  printPlan(roleConfig, deployer.address, REGISTRY_NAMES, true);

  console.log("Preflight ...");
  await assertP256Precompile();
  console.log(`  ✓ P-256 precompile at ${P256_VERIFIER} verifies a valid signature`);
  await warnUnfundedHolders(roleConfig, REGISTRY_NAMES);
  console.log("");

  // ─── Wallet Implementation (validated) ────────────
  const SovraWalletV1 = await ethers.getContractFactory("SovraWalletV1", deployer);
  const implAddr = (await upgrades.deployImplementation(SovraWalletV1)) as string;
  console.log("SovraWalletV1 deployed to:", implAddr);

  // ─── Beacon ──────────────────────────────────────────
  const SovraBeacon = await ethers.getContractFactory("SovraBeacon", deployer);
  const beacon = await SovraBeacon.deploy(
    implAddr,
    roleConfig.beaconOwner,
    roleConfig.securityCouncil
  );
  await beacon.waitForDeployment();
  const beaconAddr = await beacon.getAddress();
  console.log("SovraBeacon deployed to:", beaconAddr);

  // ─── Dispatcher ──────────────────────────────────────
  const SovraDispatcher = await ethers.getContractFactory("SovraDispatcher", deployer);
  const dispatcher = await SovraDispatcher.deploy(beaconAddr);
  await dispatcher.waitForDeployment();
  const dispatcherAddr = await dispatcher.getAddress();
  console.log("SovraDispatcher deployed to:", dispatcherAddr);

  // ─── DID Registry (UUPS proxy, validated) ─────────
  // Registries are initialized with the deployer as admin so it can grant the
  // configured roles below; it keeps or drops them per renounceDeployer.
  const SovraDIDRegistryV1 = await ethers.getContractFactory("SovraDIDRegistryV1", deployer);
  const didRegistry = await upgrades.deployProxy(SovraDIDRegistryV1, [deployer.address], { kind: "uups" });
  await didRegistry.waitForDeployment();
  const didRegistryAddr = await didRegistry.getAddress();
  console.log("SovraDIDRegistryV1 proxy deployed to:", didRegistryAddr);

  // ─── Issuer Registry (UUPS proxy, validated) ──────
  const SovraIssuerRegistryV1 = await ethers.getContractFactory("SovraIssuerRegistryV1", deployer);
  const issuerRegistry = await upgrades.deployProxy(SovraIssuerRegistryV1, [deployer.address], { kind: "uups" });
  await issuerRegistry.waitForDeployment();
  const issuerRegistryAddr = await issuerRegistry.getAddress();
  console.log("SovraIssuerRegistryV1 proxy deployed to:", issuerRegistryAddr);

  // ─── Revocation Registry (UUPS proxy, validated) ──
  const SovraRevocationRegistryV1 = await ethers.getContractFactory("SovraRevocationRegistryV1", deployer);
  const revocationRegistry = await upgrades.deployProxy(
    SovraRevocationRegistryV1,
    [deployer.address, issuerRegistryAddr],
    { kind: "uups" }
  );
  await revocationRegistry.waitForDeployment();
  const revocationRegistryAddr = await revocationRegistry.getAddress();
  console.log("SovraRevocationRegistryV1 proxy deployed to:", revocationRegistryAddr);

  // ─── Signature Registry (UUPS proxy, validated) ───
  const SignatureRegistryV1 = await ethers.getContractFactory("SignatureRegistryV1", deployer);
  const signatureRegistry = await upgrades.deployProxy(
    SignatureRegistryV1,
    [deployer.address, didRegistryAddr, issuerRegistryAddr],
    { kind: "uups" }
  );
  await signatureRegistry.waitForDeployment();
  const signatureRegistryAddr = await signatureRegistry.getAddress();
  console.log("SignatureRegistryV1 proxy deployed to:", signatureRegistryAddr);

  // ─── Output file ───────────────────────────────────
  // Written before the role transactions so a failure there cannot lose the
  // deployed addresses; rewritten with the role outcome once they succeed.
  const outputPath = deploymentsPath(`${network.name}-${chainId}.json`);
  const write = (roles: RoleOutcome) =>
    writeDeployment(
      outputPath,
      {
        network: network.name,
        chainId: Number(chainId),
        deployer: deployer.address,
        beaconOwner: roleConfig.beaconOwner,
        securityCouncil: roleConfig.securityCouncil,
        timestamp: new Date().toISOString(),
        contracts: {
          SovraWalletV1: { address: implAddr, type: "implementation" },
          SovraBeacon: { address: beaconAddr, type: "beacon" },
          SovraDispatcher: { address: dispatcherAddr, type: "contract" },
          SovraDIDRegistryV1: { address: didRegistryAddr, type: "uups-proxy" },
          SovraIssuerRegistryV1: { address: issuerRegistryAddr, type: "uups-proxy" },
          SovraRevocationRegistryV1: { address: revocationRegistryAddr, type: "uups-proxy" },
          SignatureRegistryV1: { address: signatureRegistryAddr, type: "uups-proxy" },
        } satisfies Record<string, ContractRecord>,
      },
      roleConfig,
      roles
    );

  write({ granted: [], renounced: [], complete: false });
  console.log(`\nDeployment output written to: ${outputPath}`);

  // ─── Roles ─────────────────────────────────────────
  // If this step fails, the addresses above are already on disk: fix the cause
  // and finish with `DEPLOYMENT_FILE=<file> hardhat run scripts/apply-roles.ts`.
  const registries = toRegistries({
    SovraDIDRegistryV1: didRegistry,
    SovraIssuerRegistryV1: issuerRegistry,
    SovraRevocationRegistryV1: revocationRegistry,
    SignatureRegistryV1: signatureRegistry,
  });

  console.log("");
  const { granted, renounced } = await applyRoleConfig(
    registries,
    roleConfig,
    deployer.address,
    (m) => console.log(m)
  );

  write({ granted, renounced, complete: true });

  // ─── Verification ──────────────────────────────────
  await verify(implAddr);
  await verify(beaconAddr, [implAddr, roleConfig.beaconOwner, roleConfig.securityCouncil]);
  await verify(dispatcherAddr, [beaconAddr]);
  await verify(didRegistryAddr);
  await verify(issuerRegistryAddr);
  await verify(revocationRegistryAddr);
  await verify(signatureRegistryAddr);

  // ─── Summary ──────────────────────────────────────
  console.log("\n=== Deployment Summary ===");
  console.log("SovraWalletV1:              ", implAddr);
  console.log("SovraBeacon:                ", beaconAddr);
  console.log("SovraDispatcher:            ", dispatcherAddr);
  console.log("SovraDIDRegistryV1:         ", didRegistryAddr);
  console.log("SovraIssuerRegistryV1:      ", issuerRegistryAddr);
  console.log("SovraRevocationRegistryV1:  ", revocationRegistryAddr);
  console.log("SignatureRegistryV1:        ", signatureRegistryAddr);
}

// ─── Single-registry deployment ──────────────────────

/// initialize() arguments and the getters that read them back.
function initializeArgs(
  target: RegistryName,
  deployer: string,
  existing: Record<RegistryName, string>
): { args: unknown[]; readback: Array<{ getter: string; expected: string }> } {
  switch (target) {
    case "SovraDIDRegistryV1":
    case "SovraIssuerRegistryV1":
      return { args: [deployer], readback: [] };
    case "SovraRevocationRegistryV1":
      return {
        args: [deployer, existing.SovraIssuerRegistryV1],
        readback: [{ getter: "issuerRegistry", expected: existing.SovraIssuerRegistryV1 }],
      };
    case "SignatureRegistryV1":
      return {
        args: [deployer, existing.SovraDIDRegistryV1, existing.SovraIssuerRegistryV1],
        readback: [
          { getter: "keyRegistry", expected: existing.SovraDIDRegistryV1 },
          { getter: "authorizationRegistry", expected: existing.SovraIssuerRegistryV1 },
        ],
      };
  }
}

async function deployOne(
  target: RegistryName,
  deployer: Wallet,
  chainId: bigint,
  roleConfig: NetworkRoleConfig
): Promise<void> {
  // The target's initialize() may need one of these, and the role step covers
  // the whole config.
  const existing = {} as Record<RegistryName, string>;
  for (const name of REGISTRY_NAMES) {
    if (name !== target) existing[name] = requireAddress(ADDRESS_ENV[name]);
  }

  console.log(`\n=== Deploying ${target} only ===`);
  for (const name of REGISTRY_NAMES) {
    if (name !== target) console.log(`${name} (existing): ${existing[name]}`);
  }
  printPlan(roleConfig, deployer.address, [target], false);

  // ─── Preflight ─────────────────────────────────────
  console.log("Preflight ...");
  for (const name of REGISTRY_NAMES) {
    if (name !== target) await assertHasCode(existing[name], ADDRESS_ENV[name]);
  }
  if (target === "SignatureRegistryV1") {
    await assertRegistryInterfaces(
      existing.SovraDIDRegistryV1,
      existing.SovraIssuerRegistryV1
    );
    console.log("  ✓ Existing registries answer their interfaces");
    await assertP256Precompile();
    console.log(`  ✓ P-256 precompile at ${P256_VERIFIER} verifies a valid signature`);
  }
  await warnUnfundedHolders(roleConfig, [target]);
  console.log("");

  // ─── Proxy (validated) ─────────────────────────────
  const { args, readback } = initializeArgs(target, deployer.address, existing);
  const factory = await ethers.getContractFactory(target, deployer);
  const proxy = await upgrades.deployProxy(factory, args, { kind: "uups" });
  await proxy.waitForDeployment();
  const address = await proxy.getAddress();
  console.log(`${target} proxy deployed to:`, address);

  // None of these can be changed after initialize(), so a wrong one has to
  // surface here.
  const view = proxy.connect(ethers.provider) as unknown as AddressGetters;
  for (const { getter, expected } of readback) {
    const actual = await view[getter](READ_AS_NOBODY);
    if (ethers.getAddress(actual) !== expected) {
      fail(
        `${target}.${getter}() is ${actual}, expected ${expected} — the proxy at ` +
          `${address} is mis-wired and must be redeployed`
      );
    }
  }
  if (readback.length > 0) {
    const matches = readback.length === 1 ? "matches" : "match";
    console.log(
      `  ✓ ${readback.map((r) => r.getter).join(", ")} ${matches} the addresses passed in`
    );
  }

  // ─── Output file ───────────────────────────────────
  // Written before the role transactions so a failure there cannot lose the
  // address. Named apart from the full deploy record.
  const outputPath = deploymentsPath(`${network.name}-${chainId}-${target}.json`);
  const contracts = {} as Record<string, ContractRecord>;
  for (const name of REGISTRY_NAMES) {
    contracts[name] =
      name === target
        ? { address, type: "uups-proxy" }
        : { address: existing[name], type: "uups-proxy", preexisting: true };
  }

  const write = (roles: RoleOutcome) =>
    writeDeployment(
      outputPath,
      {
        network: network.name,
        chainId: Number(chainId),
        deployer: deployer.address,
        deployed: target,
        timestamp: new Date().toISOString(),
        contracts,
      },
      roleConfig,
      roles
    );

  write({ granted: [], renounced: [], complete: false });
  console.log(`\nDeployment output written to: ${outputPath}`);

  // ─── Roles ─────────────────────────────────────────
  // applyRoleConfig covers the whole config: roles already in place are read and
  // skipped, so this also confirms the others still match. If it fails, the
  // address is on disk — finish with
  // `DEPLOYMENT_FILE=<file> hardhat run scripts/apply-roles.ts`.
  const addresses = { ...existing, [target]: address } as Record<RegistryName, string>;
  const registries = await attachRegistries(addresses, deployer);

  console.log("");
  const { granted, renounced } = await applyRoleConfig(
    registries,
    roleConfig,
    deployer.address,
    (m) => console.log(m)
  );

  write({ granted, renounced, complete: true });

  await verify(address);

  // ─── Summary ──────────────────────────────────────
  console.log("\n=== Deployment Summary ===");
  console.log(`${target}:`, address);
  for (const { getter, expected } of readback) {
    console.log(`  ${getter}:`, expected);
  }
  if (target === "SignatureRegistryV1") {
    console.log("\nNext: set this in infra/ansible/playbooks/ini/config-<env>.ini and");
    console.log("reconfigure the api component, or the backend still refuses to sign.\n");
    console.log(`signature_registry_address=${address}`);
  }
}

// ─── Entry point ─────────────────────────────────────

export async function deploy(options: DeployOptions = {}): Promise<void> {
  if (!process.env.DEPLOYER_PRIVATE_KEY) {
    fail("DEPLOYER_PRIVATE_KEY environment variable is required");
  }
  const deployer = new ethers.Wallet(process.env.DEPLOYER_PRIVATE_KEY, ethers.provider);
  console.log("Deploying from:", deployer.address);

  const chainId = (await ethers.provider.getNetwork()).chainId;

  // ─── Role config (before any transaction) ──────────
  const roleConfig = loadChainConfig(network.name);
  assertDeployerHandoff(roleConfig, deployer.address);

  if (options.contract === undefined) {
    await deployAll(deployer, chainId, roleConfig);
  } else {
    await deployOne(resolveTarget(options.contract), deployer, chainId, roleConfig);
  }
}
