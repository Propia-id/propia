import { run } from "hardhat";
import * as fs from "fs";
import * as path from "path";

interface DeploymentOutput {
  deployer: string;
  beaconOwner: string;
  securityCouncil: string;
  contracts: {
    SovraWalletV1: { address: string };
    SovraBeacon: { address: string };
    SovraDispatcher: { address: string };
    SovraDIDRegistryV1: { address: string };
    SovraIssuerRegistryV1: { address: string };
  };
}

async function verify(address: string, constructorArguments: unknown[] = []) {
  console.log(`Verifying ${address} ...`);
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

async function main() {
  const deploymentFile = process.env.DEPLOYMENT_FILE;
  if (!deploymentFile) {
    console.error("Error: DEPLOYMENT_FILE environment variable is required (path to deployment JSON)");
    process.exit(1);
  }

  const filePath = path.resolve(deploymentFile);
  if (!fs.existsSync(filePath)) {
    console.error(`Error: Deployment file not found: ${filePath}`);
    process.exit(1);
  }

  const deployment: DeploymentOutput = JSON.parse(fs.readFileSync(filePath, "utf-8"));
  const { contracts, beaconOwner, securityCouncil } = deployment;

  // The beacon's owner comes from chain/config.json, not from the deploy key.
  if (!beaconOwner) {
    console.error(
      `Error: ${filePath} has no "beaconOwner" — it predates chain/config.json. Re-run the deploy or add the field.`
    );
    process.exit(1);
  }

  console.log("Verifying contracts from:", filePath);

  await verify(contracts.SovraWalletV1.address);
  await verify(contracts.SovraBeacon.address, [
    contracts.SovraWalletV1.address,
    beaconOwner,
    securityCouncil,
  ]);
  await verify(contracts.SovraDispatcher.address, [contracts.SovraBeacon.address]);
  await verify(contracts.SovraDIDRegistryV1.address);
  await verify(contracts.SovraIssuerRegistryV1.address);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
