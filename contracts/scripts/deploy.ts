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

  const SovraDispatcher = await ethers.getContractFactory("SovraDispatcher", deployer);
  const dispatcher = await SovraDispatcher.deploy(implAddr);
  const dispatcherTx = dispatcher.deploymentTransaction()!;
  console.log("SovraDispatcher deploy tx:", dispatcherTx.hash);
  await dispatcher.waitForDeployment();
  const dispatcherAddr = await dispatcher.getAddress();
  console.log("SovraDispatcher deployed to:", dispatcherAddr);

  const dispatcherCode = await ethers.provider.getCode(dispatcherAddr);
  if (dispatcherCode === "0x") {
    throw new Error(`No code at SovraDispatcher address ${dispatcherAddr} — deployment failed`);
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
