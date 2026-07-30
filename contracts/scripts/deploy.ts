import { ethers, upgrades, run, network } from "hardhat";
import * as fs from "fs";
import * as path from "path";
import {
  assertDeployerHandoff,
  handoffWarnings,
  loadChainConfig,
  NetworkRoleConfig,
  REGISTRY_NAMES,
  REGISTRY_ROLES,
} from "./chain-config";
import { applyRoleConfig, RoleGrant, RoleRenounce } from "./roles";
import { toRegistries } from "./registries";

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

function printPlan(config: NetworkRoleConfig, deployer: string) {
  console.log(`\n=== Role plan (chain/config.json -> ${config.network}) ===`);
  console.log("Beacon owner:              ", config.beaconOwner);
  console.log("Beacon security council:   ", config.securityCouncil);
  for (const name of REGISTRY_NAMES) {
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

async function main() {
  if (!process.env.DEPLOYER_PRIVATE_KEY) {
    console.error("Error: DEPLOYER_PRIVATE_KEY environment variable is required");
    process.exit(1);
  }
  const deployer = new ethers.Wallet(process.env.DEPLOYER_PRIVATE_KEY, ethers.provider);
  console.log("Deploying from:", deployer.address);

  // ─── Role config (before any transaction) ──────────
  const roleConfig = loadChainConfig(network.name);
  assertDeployerHandoff(roleConfig, deployer.address);
  printPlan(roleConfig, deployer.address);

  // ─── Wallet Implementation (validated) ────────────
  const SovraWalletV1 = await ethers.getContractFactory("SovraWalletV1", deployer);
  const implAddr = await upgrades.deployImplementation(SovraWalletV1) as string;
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

  // ─── Output file ───────────────────────────────────
  // Written before the role transactions so a failure there cannot lose the
  // deployed addresses; rewritten with the role outcome once they succeed.
  const chainId = (await ethers.provider.getNetwork()).chainId;
  const deploymentsDir = path.join(__dirname, "..", "deployments");
  if (!fs.existsSync(deploymentsDir)) {
    fs.mkdirSync(deploymentsDir, { recursive: true });
  }
  const outputPath = path.join(deploymentsDir, `${network.name}-${chainId}.json`);

  const writeOutput = (roles: {
    granted: RoleGrant[];
    renounced: RoleRenounce[];
    complete: boolean;
  }) => {
    const output = {
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
      },
      roles: {
        configured: roleConfig.roles,
        renounceDeployer: roleConfig.renounceDeployer,
        granted: roles.granted,
        renounced: roles.renounced,
        applied: roles.complete,
      },
    };
    fs.writeFileSync(outputPath, JSON.stringify(output, null, 2) + "\n");
  };

  writeOutput({ granted: [], renounced: [], complete: false });
  console.log(`\nDeployment output written to: ${outputPath}`);

  // ─── Roles ─────────────────────────────────────────
  // If this step fails, the addresses above are already on disk: fix the cause
  // and finish with `DEPLOYMENT_FILE=<file> hardhat run scripts/apply-roles.ts`.
  const registries = toRegistries({
    SovraDIDRegistryV1: didRegistry,
    SovraIssuerRegistryV1: issuerRegistry,
    SovraRevocationRegistryV1: revocationRegistry,
  });

  console.log("");
  const { granted, renounced } = await applyRoleConfig(
    registries,
    roleConfig,
    deployer.address,
    (m) => console.log(m)
  );

  writeOutput({ granted, renounced, complete: true });

  // ─── Verification ──────────────────────────────────
  await verify(implAddr);
  await verify(beaconAddr, [implAddr, roleConfig.beaconOwner, roleConfig.securityCouncil]);
  await verify(dispatcherAddr, [beaconAddr]);
  await verify(didRegistryAddr);
  await verify(issuerRegistryAddr);
  await verify(revocationRegistryAddr);

  // ─── Summary ──────────────────────────────────────
  console.log("\n=== Deployment Summary ===");
  console.log("SovraWalletV1:              ", implAddr);
  console.log("SovraBeacon:                ", beaconAddr);
  console.log("SovraDispatcher:            ", dispatcherAddr);
  console.log("SovraDIDRegistryV1:         ", didRegistryAddr);
  console.log("SovraIssuerRegistryV1:      ", issuerRegistryAddr);
  console.log("SovraRevocationRegistryV1:  ", revocationRegistryAddr);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
