import { ethers, upgrades } from "hardhat";

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
