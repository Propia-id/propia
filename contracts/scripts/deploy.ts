import { ethers } from "hardhat";

async function main() {
  if (!process.env.DEPLOYER_PRIVATE_KEY) {
    console.error("Error: DEPLOYER_PRIVATE_KEY environment variable is required");
    process.exit(1);
  }
  const deployer = new ethers.Wallet(process.env.DEPLOYER_PRIVATE_KEY, ethers.provider);
  console.log("Deploying from:", deployer.address);

  const SovraWalletV1 = await ethers.getContractFactory("SovraWalletV1", deployer);
  const implementation = await SovraWalletV1.deploy();
  const implTx = implementation.deploymentTransaction()!;
  console.log("SovraWalletV1 deploy tx:", implTx.hash);
  await implementation.waitForDeployment();
  const implAddr = await implementation.getAddress();
  console.log("SovraWalletV1 deployed to:", implAddr);

  const implCode = await ethers.provider.getCode(implAddr);
  if (implCode === "0x") {
    throw new Error(`No code at SovraWalletV1 address ${implAddr} — deployment failed`);
  }

  // ─── Beacon ──────────────────────────────────────────
  const SovraBeacon = await ethers.getContractFactory("SovraBeacon", deployer);
  const beacon = await SovraBeacon.deploy(implAddr, deployer.address, deployer.address);
  const beaconTx = beacon.deploymentTransaction()!;
  console.log("SovraBeacon deploy tx:", beaconTx.hash);
  await beacon.waitForDeployment();
  const beaconAddr = await beacon.getAddress();
  console.log("SovraBeacon deployed to:", beaconAddr);

  const beaconCode = await ethers.provider.getCode(beaconAddr);
  if (beaconCode === "0x") {
    throw new Error(`No code at SovraBeacon address ${beaconAddr} — deployment failed`);
  }

  // ─── Dispatcher ──────────────────────────────────────
  const SovraDispatcher = await ethers.getContractFactory("SovraDispatcher", deployer);
  const dispatcher = await SovraDispatcher.deploy(beaconAddr);
  const dispatcherTx = dispatcher.deploymentTransaction()!;
  console.log("SovraDispatcher deploy tx:", dispatcherTx.hash);
  await dispatcher.waitForDeployment();
  const dispatcherAddr = await dispatcher.getAddress();
  console.log("SovraDispatcher deployed to:", dispatcherAddr);

  const dispatcherCode = await ethers.provider.getCode(dispatcherAddr);
  if (dispatcherCode === "0x") {
    throw new Error(`No code at SovraDispatcher address ${dispatcherAddr} — deployment failed`);
  }

  // ─── Proxy factory (shared by UUPS deployments) ────
  const ERC1967Proxy = await ethers.getContractFactory("ERC1967Proxy", deployer);

  // ─── DID Registry (UUPS proxy) ─────────────────────
  const SovraDIDRegistryV1 = await ethers.getContractFactory("SovraDIDRegistryV1", deployer);
  const didRegistryImpl = await SovraDIDRegistryV1.deploy();
  await didRegistryImpl.waitForDeployment();
  const didRegistryImplAddr = await didRegistryImpl.getAddress();
  console.log("SovraDIDRegistryV1 impl deployed to:", didRegistryImplAddr);

  const didInitData = SovraDIDRegistryV1.interface.encodeFunctionData("initialize", [deployer.address]);
  const didRegistryProxy = await ERC1967Proxy.deploy(didRegistryImplAddr, didInitData);
  await didRegistryProxy.waitForDeployment();
  const didRegistryAddr = await didRegistryProxy.getAddress();
  console.log("SovraDIDRegistryV1 proxy deployed to:", didRegistryAddr);

  const didRegistryCode = await ethers.provider.getCode(didRegistryAddr);
  if (didRegistryCode === "0x") {
    throw new Error(`No code at SovraDIDRegistryV1 proxy address ${didRegistryAddr} — deployment failed`);
  }

  // ─── Issuer Registry (UUPS proxy) ─────────────────
  const SovraIssuerRegistryV1 = await ethers.getContractFactory("SovraIssuerRegistryV1", deployer);
  const issuerRegistryImpl = await SovraIssuerRegistryV1.deploy();
  await issuerRegistryImpl.waitForDeployment();
  const issuerRegistryImplAddr = await issuerRegistryImpl.getAddress();
  console.log("SovraIssuerRegistryV1 impl deployed to:", issuerRegistryImplAddr);

  const initData = SovraIssuerRegistryV1.interface.encodeFunctionData("initialize", [deployer.address]);
  const issuerRegistryProxy = await ERC1967Proxy.deploy(issuerRegistryImplAddr, initData);
  await issuerRegistryProxy.waitForDeployment();
  const issuerRegistryAddr = await issuerRegistryProxy.getAddress();
  console.log("SovraIssuerRegistryV1 proxy deployed to:", issuerRegistryAddr);

  const issuerRegistryCode = await ethers.provider.getCode(issuerRegistryAddr);
  if (issuerRegistryCode === "0x") {
    throw new Error(`No code at SovraIssuerRegistryV1 proxy address ${issuerRegistryAddr} — deployment failed`);
  }

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
