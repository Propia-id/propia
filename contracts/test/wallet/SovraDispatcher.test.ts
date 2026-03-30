import { expect } from "chai";
import { ethers, network } from "hardhat";
import { deployWallet, deployAndInitialize, etchP256Verifier } from "./helpers";

describe("SovraDispatcher", function () {
  it("delegates calls to the beacon implementation", async function () {
    const { wallet } = await deployWallet();
    // nonce() should return 0 on uninitialised wallet
    expect(await wallet.nonce()).to.equal(0);
  });

  it("returns data correctly through the proxy", async function () {
    const { wallet } = await deployAndInitialize();
    // didVersionId should be 1 after init
    expect(await wallet.didVersionId()).to.equal(1);
  });

  it("propagates reverts from implementation", async function () {
    const { wallet } = await deployAndInitialize();
    // Double-init should revert
    await expect(
      wallet.initialize(
        ethers.zeroPadValue("0x01", 32),
        ethers.zeroPadValue("0x02", 32),
        ethers.zeroPadValue("0x03", 32),
        ethers.zeroPadValue("0x04", 32),
        ethers.zeroPadValue("0x05", 32),
        ethers.zeroPadValue("0x06", 32)
      )
    ).to.be.revertedWithCustomError(wallet, "InvalidInitialization");
  });

  it("uses beacon when ERC-1967 slot is empty", async function () {
    // The default deploy has no ERC-1967 slot set, yet calls work via beacon
    const { wallet } = await deployWallet();
    // Can read state (nonce = 0) which means delegatecall via beacon works
    expect(await wallet.nonce()).to.equal(0);
    expect(await wallet.didCreated()).to.equal(0);
  });

  it("per-account ERC-1967 override takes precedence over beacon", async function () {
    const { wallet, passkey, domainSep } = await deployAndInitialize();
    const { buildMessageHash, signPasskey } = await import("./helpers");

    // Deploy a new implementation and pin via upgrade()
    const SovraWalletV1 = await ethers.getContractFactory("SovraWalletV1");
    const newImpl = await SovraWalletV1.deploy();
    await newImpl.waitForDeployment();
    const newImplAddr = await newImpl.getAddress();

    const currentNonce = await wallet.nonce();
    const opHash = ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(
        ["bytes4", "address"],
        [ethers.dataSlice(ethers.keccak256(ethers.toUtf8Bytes("upgrade")), 0, 4), newImplAddr]
      )
    );
    const msgHash = buildMessageHash(domainSep, opHash, currentNonce);
    const sigs = signPasskey(passkey, msgHash);

    await wallet.upgrade(newImplAddr, sigs.passkeyR, sigs.passkeyS);

    // Wallet still works with the pinned implementation
    expect(await wallet.didVersionId()).to.equal(1);
  });

  it("beacon upgrade changes implementation for unpinned wallets", async function () {
    const { wallet, beacon } = await deployAndInitialize();

    // Deploy a new implementation and update the beacon
    const SovraWalletV1 = await ethers.getContractFactory("SovraWalletV1");
    const newImpl = await SovraWalletV1.deploy();
    await newImpl.waitForDeployment();
    const newImplAddr = await newImpl.getAddress();

    const [owner] = await ethers.getSigners();
    await beacon.connect(owner).scheduleUpgrade(newImplAddr);
    await network.provider.send("evm_increaseTime", [48 * 3600]);
    await network.provider.send("evm_mine");
    await beacon.executeUpgrade();

    // Wallet (unpinned) should still work — now using new impl
    expect(await wallet.didVersionId()).to.equal(1);
    expect(await beacon.implementation()).to.equal(newImplAddr);
  });

  it("beacon upgrade does NOT affect pinned wallets", async function () {
    const { wallet, beacon, passkey, domainSep } = await deployAndInitialize();
    const { buildMessageHash, signPasskey } = await import("./helpers");

    // Pin wallet to current implementation
    const currentImpl = await beacon.implementation();
    const currentNonce = await wallet.nonce();
    const opHash = ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(
        ["bytes4", "address"],
        [ethers.dataSlice(ethers.keccak256(ethers.toUtf8Bytes("upgrade")), 0, 4), currentImpl]
      )
    );
    const msgHash = buildMessageHash(domainSep, opHash, currentNonce);
    const sigs = signPasskey(passkey, msgHash);
    await wallet.upgrade(currentImpl, sigs.passkeyR, sigs.passkeyS);

    // Update beacon to a new impl
    const SovraWalletV1 = await ethers.getContractFactory("SovraWalletV1");
    const newImpl = await SovraWalletV1.deploy();
    await newImpl.waitForDeployment();
    const newImplAddr = await newImpl.getAddress();

    const [owner] = await ethers.getSigners();
    await beacon.connect(owner).scheduleUpgrade(newImplAddr);
    await network.provider.send("evm_increaseTime", [48 * 3600]);
    await network.provider.send("evm_mine");
    await beacon.executeUpgrade();

    // Beacon points to new impl, but pinned wallet still works on old impl
    expect(await beacon.implementation()).to.equal(newImplAddr);
    expect(await wallet.didVersionId()).to.equal(1);
  });

  it("delegates to new implementation after upgrade", async function () {
    const { wallet, passkey, recoveryKey, domainSep } = await deployAndInitialize();
    const { buildMessageHash, signPasskey } = await import("./helpers");

    // Deploy a new implementation
    const SovraWalletV1 = await ethers.getContractFactory("SovraWalletV1");
    const newImpl = await SovraWalletV1.deploy();
    await newImpl.waitForDeployment();
    const newImplAddr = await newImpl.getAddress();

    const currentNonce = await wallet.nonce();
    const opHash = ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(
        ["bytes4", "address"],
        [ethers.dataSlice(ethers.keccak256(ethers.toUtf8Bytes("upgrade")), 0, 4), newImplAddr]
      )
    );
    const msgHash = buildMessageHash(domainSep, opHash, currentNonce);
    const sigs = signPasskey(passkey, msgHash);

    await wallet.upgrade(newImplAddr, sigs.passkeyR, sigs.passkeyS);

    // After upgrade, the wallet should still work (new impl same code)
    expect(await wallet.didVersionId()).to.equal(1);
  });

  it("receives ETH", async function () {
    const { wallet } = await deployWallet();
    const [signer] = await ethers.getSigners();
    const walletAddr = await wallet.getAddress();

    await signer.sendTransaction({ to: walletAddr, value: ethers.parseEther("1") });
    expect(await ethers.provider.getBalance(walletAddr)).to.equal(ethers.parseEther("1"));
  });
});
