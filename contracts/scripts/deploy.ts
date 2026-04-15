import { ethers, upgrades, run, network } from "hardhat";
import * as fs from "fs";
import * as path from "path";

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

async function main() {
  if (!process.env.DEPLOYER_PRIVATE_KEY) {
    console.error("Error: DEPLOYER_PRIVATE_KEY environment variable is required");
    process.exit(1);
  }
  const deployer = new ethers.Wallet(process.env.DEPLOYER_PRIVATE_KEY, ethers.provider);
  console.log("Deploying from:", deployer.address);

  // ─── Wallet Implementation (validated) ────────────
  const SovraWalletV1 = await ethers.getContractFactory("SovraWalletV1", deployer);
  const implAddr = await upgrades.deployImplementation(SovraWalletV1) as string;
  console.log("SovraWalletV1 deployed to:", implAddr);

  // ─── Beacon ──────────────────────────────────────────
  const councilAddr = process.env.SECURITY_COUNCIL_ADDRESS || deployer.address;
  if (councilAddr === deployer.address) {
    console.warn("⚠ WARNING: deployer is being used as security council. Set SECURITY_COUNCIL_ADDRESS for production deployments.");
  }
  const SovraBeacon = await ethers.getContractFactory("SovraBeacon", deployer);
  const beacon = await SovraBeacon.deploy(implAddr, deployer.address, councilAddr);
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

  // ─── Verification ──────────────────────────────────
  await verify(implAddr);
  await verify(beaconAddr, [implAddr, deployer.address, councilAddr]);
  await verify(dispatcherAddr, [beaconAddr]);
  await verify(didRegistryAddr);
  await verify(issuerRegistryAddr);

  // ─── Output file ───────────────────────────────────
  const chainId = (await ethers.provider.getNetwork()).chainId;
  const output = {
    network: network.name,
    chainId: Number(chainId),
    deployer: deployer.address,
    securityCouncil: councilAddr,
    timestamp: new Date().toISOString(),
    contracts: {
      SovraWalletV1: { address: implAddr, type: "implementation" },
      SovraBeacon: { address: beaconAddr, type: "beacon" },
      SovraDispatcher: { address: dispatcherAddr, type: "contract" },
      SovraDIDRegistryV1: { address: didRegistryAddr, type: "uups-proxy" },
      SovraIssuerRegistryV1: { address: issuerRegistryAddr, type: "uups-proxy" },
    },
  };

  const deploymentsDir = path.join(__dirname, "..", "deployments");
  if (!fs.existsSync(deploymentsDir)) {
    fs.mkdirSync(deploymentsDir, { recursive: true });
  }
  const outputPath = path.join(deploymentsDir, `${network.name}-${chainId}.json`);
  fs.writeFileSync(outputPath, JSON.stringify(output, null, 2) + "\n");
  console.log(`\nDeployment output written to: ${outputPath}`);

  // ─── Summary ──────────────────────────────────────
  console.log("\n=== Deployment Summary ===");
  console.log("SovraWalletV1:          ", implAddr);
  console.log("SovraBeacon:            ", beaconAddr);
  console.log("SovraDispatcher:        ", dispatcherAddr);
  console.log("SovraDIDRegistryV1:     ", didRegistryAddr);
  console.log("SovraIssuerRegistryV1:  ", issuerRegistryAddr);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
