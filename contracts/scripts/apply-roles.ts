import { ethers, network } from "hardhat";
import * as fs from "fs";
import * as path from "path";
import {
  assertDeployerHandoff,
  handoffWarnings,
  loadChainConfig,
  REGISTRY_NAMES,
  RegistryName,
} from "./chain-config";
import { applyRoleConfig } from "./roles";
import { attachRegistries } from "./registries";

/// Applies chain/config.json to registries that are already deployed — for a
/// deployment whose role step failed after the contracts went out. Idempotent:
/// roles already in place are skipped, so it is safe to re-run.

interface DeploymentFile {
  network?: string;
  contracts?: Partial<Record<RegistryName, { address?: string }>>;
  roles?: { applied?: boolean };
}

function fail(message: string): never {
  console.error(`Error: ${message}`);
  process.exit(1);
}

async function main() {
  if (!process.env.DEPLOYER_PRIVATE_KEY) {
    fail("DEPLOYER_PRIVATE_KEY environment variable is required");
  }
  if (!process.env.DEPLOYMENT_FILE) {
    fail("DEPLOYMENT_FILE environment variable is required (path to the deployment JSON)");
  }

  const filePath = path.resolve(process.env.DEPLOYMENT_FILE);
  if (!fs.existsSync(filePath)) fail(`deployment file not found: ${filePath}`);

  const deployment: DeploymentFile = JSON.parse(fs.readFileSync(filePath, "utf-8"));
  if (deployment.network && deployment.network !== network.name) {
    fail(
      `${filePath} was written for network "${deployment.network}" but this run is on ` +
        `"${network.name}" — pass --network ${deployment.network}`
    );
  }

  const addresses = {} as Record<RegistryName, string>;
  for (const name of REGISTRY_NAMES) {
    const address = deployment.contracts?.[name]?.address;
    if (!address) fail(`${filePath} has no address for ${name}`);
    addresses[name] = address;
  }

  const deployer = new ethers.Wallet(process.env.DEPLOYER_PRIVATE_KEY!, ethers.provider);
  const roleConfig = loadChainConfig(network.name);
  assertDeployerHandoff(roleConfig, deployer.address);

  console.log("Applying roles from:", filePath);
  console.log("Acting as:", deployer.address);
  for (const name of REGISTRY_NAMES) {
    console.log(`  ${name}: ${addresses[name]}`);
  }
  for (const warning of handoffWarnings(roleConfig, deployer.address)) {
    console.warn(`⚠ WARNING: ${warning}`);
  }
  console.log("");

  const registries = await attachRegistries(addresses, deployer);
  const { granted, renounced } = await applyRoleConfig(
    registries,
    roleConfig,
    deployer.address,
    (m) => console.log(m)
  );

  // Record the outcome without disturbing the rest of the deployment file.
  const updated = {
    ...deployment,
    roles: {
      configured: roleConfig.roles,
      renounceDeployer: roleConfig.renounceDeployer,
      granted,
      renounced,
      applied: true,
    },
  };
  fs.writeFileSync(filePath, JSON.stringify(updated, null, 2) + "\n");
  console.log(`\nDeployment file updated: ${filePath}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
