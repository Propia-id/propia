import { expect } from "chai";
import { ethers, network } from "hardhat";
import { etchP256Verifier } from "./helpers";

describe("SovraBeacon", function () {
  async function deployBeaconFixture() {
    await etchP256Verifier();

    const [owner, council, other] = await ethers.getSigners();

    const SovraWalletV1 = await ethers.getContractFactory("SovraWalletV1");
    const impl = await SovraWalletV1.deploy();
    await impl.waitForDeployment();
    const implAddr = await impl.getAddress();

    const SovraBeacon = await ethers.getContractFactory("SovraBeacon");
    const beacon = await SovraBeacon.deploy(implAddr, owner.address, council.address);
    await beacon.waitForDeployment();

    // Deploy a second implementation for upgrade tests
    const impl2 = await SovraWalletV1.deploy();
    await impl2.waitForDeployment();
    const impl2Addr = await impl2.getAddress();

    return { beacon, impl, implAddr, impl2, impl2Addr, owner, council, other };
  }

  // ─── Construction ──────────────────────────────────────

  describe("constructor", function () {
    it("sets initial implementation", async function () {
      const { beacon, implAddr } = await deployBeaconFixture();
      expect(await beacon.implementation()).to.equal(implAddr);
    });

    it("sets owner and security council", async function () {
      const { beacon, owner, council } = await deployBeaconFixture();
      expect(await beacon.owner()).to.equal(owner.address);
      expect(await beacon.securityCouncil()).to.equal(council.address);
    });

    it("reverts for zero implementation address", async function () {
      const [owner, council] = await ethers.getSigners();
      const SovraBeacon = await ethers.getContractFactory("SovraBeacon");
      await expect(
        SovraBeacon.deploy(ethers.ZeroAddress, owner.address, council.address)
      ).to.be.revertedWithCustomError(SovraBeacon, "InvalidImplementation");
    });

    it("reverts for non-contract implementation", async function () {
      const [owner, council, random] = await ethers.getSigners();
      const SovraBeacon = await ethers.getContractFactory("SovraBeacon");
      await expect(
        SovraBeacon.deploy(random.address, owner.address, council.address)
      ).to.be.revertedWithCustomError(SovraBeacon, "NotAContract");
    });

    it("reverts for zero security council", async function () {
      await etchP256Verifier();
      const [owner] = await ethers.getSigners();
      const SovraWalletV1 = await ethers.getContractFactory("SovraWalletV1");
      const impl = await SovraWalletV1.deploy();
      await impl.waitForDeployment();

      const SovraBeacon = await ethers.getContractFactory("SovraBeacon");
      await expect(
        SovraBeacon.deploy(await impl.getAddress(), owner.address, ethers.ZeroAddress)
      ).to.be.revertedWithCustomError(SovraBeacon, "InvalidSecurityCouncil");
    });
  });

  // ─── Standard (Timelocked) Upgrade ─────────────────────

  describe("scheduleUpgrade", function () {
    it("schedules an upgrade with correct activation time", async function () {
      const { beacon, impl2Addr, owner } = await deployBeaconFixture();

      const tx = await beacon.connect(owner).scheduleUpgrade(impl2Addr);
      const receipt = await tx.wait();
      const block = await ethers.provider.getBlock(receipt!.blockNumber);

      expect(await beacon.pendingImplementation()).to.equal(impl2Addr);
      const expectedActivation = BigInt(block!.timestamp) + BigInt(48 * 3600);
      expect(await beacon.activationTime()).to.equal(expectedActivation);
    });

    it("emits UpgradeScheduled event", async function () {
      const { beacon, impl2Addr, owner } = await deployBeaconFixture();
      await expect(beacon.connect(owner).scheduleUpgrade(impl2Addr))
        .to.emit(beacon, "UpgradeScheduled");
    });

    it("reverts for non-owner", async function () {
      const { beacon, impl2Addr, other } = await deployBeaconFixture();
      await expect(
        beacon.connect(other).scheduleUpgrade(impl2Addr)
      ).to.be.revertedWithCustomError(beacon, "OwnableUnauthorizedAccount");
    });

    it("reverts for zero address", async function () {
      const { beacon, owner } = await deployBeaconFixture();
      await expect(
        beacon.connect(owner).scheduleUpgrade(ethers.ZeroAddress)
      ).to.be.revertedWithCustomError(beacon, "InvalidImplementation");
    });

    it("reverts for non-contract address", async function () {
      const { beacon, owner, other } = await deployBeaconFixture();
      await expect(
        beacon.connect(owner).scheduleUpgrade(other.address)
      ).to.be.revertedWithCustomError(beacon, "NotAContract");
    });
  });

  describe("executeUpgrade", function () {
    it("executes after timelock elapsed", async function () {
      const { beacon, implAddr, impl2Addr, owner } = await deployBeaconFixture();

      await beacon.connect(owner).scheduleUpgrade(impl2Addr);

      // Fast-forward past timelock
      await network.provider.send("evm_increaseTime", [48 * 3600]);
      await network.provider.send("evm_mine");

      await beacon.executeUpgrade();

      expect(await beacon.implementation()).to.equal(impl2Addr);
      expect(await beacon.pendingImplementation()).to.equal(ethers.ZeroAddress);
      expect(await beacon.activationTime()).to.equal(0);
    });

    it("emits UpgradeExecuted event", async function () {
      const { beacon, impl2Addr, owner } = await deployBeaconFixture();

      await beacon.connect(owner).scheduleUpgrade(impl2Addr);
      await network.provider.send("evm_increaseTime", [48 * 3600]);
      await network.provider.send("evm_mine");

      await expect(beacon.executeUpgrade())
        .to.emit(beacon, "UpgradeExecuted")
        .withArgs(impl2Addr);
    });

    it("callable by anyone after timelock", async function () {
      const { beacon, impl2Addr, owner, other } = await deployBeaconFixture();

      await beacon.connect(owner).scheduleUpgrade(impl2Addr);
      await network.provider.send("evm_increaseTime", [48 * 3600]);
      await network.provider.send("evm_mine");

      // Non-owner can execute
      await beacon.connect(other).executeUpgrade();
      expect(await beacon.implementation()).to.equal(impl2Addr);
    });

    it("reverts before timelock elapsed", async function () {
      const { beacon, impl2Addr, owner } = await deployBeaconFixture();

      await beacon.connect(owner).scheduleUpgrade(impl2Addr);

      // Only advance 1 hour
      await network.provider.send("evm_increaseTime", [3600]);
      await network.provider.send("evm_mine");

      await expect(beacon.executeUpgrade())
        .to.be.revertedWithCustomError(beacon, "TimelockNotElapsed");
    });

    it("reverts when no pending upgrade", async function () {
      const { beacon } = await deployBeaconFixture();
      await expect(beacon.executeUpgrade())
        .to.be.revertedWithCustomError(beacon, "NoPendingUpgrade");
    });
  });

  describe("cancelUpgrade", function () {
    it("clears pending upgrade", async function () {
      const { beacon, impl2Addr, owner } = await deployBeaconFixture();

      await beacon.connect(owner).scheduleUpgrade(impl2Addr);
      await beacon.connect(owner).cancelUpgrade();

      expect(await beacon.pendingImplementation()).to.equal(ethers.ZeroAddress);
      expect(await beacon.activationTime()).to.equal(0);
    });

    it("emits UpgradeCancelled event", async function () {
      const { beacon, impl2Addr, owner } = await deployBeaconFixture();

      await beacon.connect(owner).scheduleUpgrade(impl2Addr);
      await expect(beacon.connect(owner).cancelUpgrade())
        .to.emit(beacon, "UpgradeCancelled");
    });

    it("reverts for non-owner", async function () {
      const { beacon, impl2Addr, owner, other } = await deployBeaconFixture();

      await beacon.connect(owner).scheduleUpgrade(impl2Addr);
      await expect(
        beacon.connect(other).cancelUpgrade()
      ).to.be.revertedWithCustomError(beacon, "OwnableUnauthorizedAccount");
    });

    it("reverts when no pending upgrade", async function () {
      const { beacon, owner } = await deployBeaconFixture();
      await expect(
        beacon.connect(owner).cancelUpgrade()
      ).to.be.revertedWithCustomError(beacon, "NoPendingUpgrade");
    });
  });

  // ─── Emergency Upgrade ────────────────────────────────

  describe("emergencyUpgrade", function () {
    it("upgrades immediately when called by security council", async function () {
      const { beacon, impl2Addr, council } = await deployBeaconFixture();

      await beacon.connect(council).emergencyUpgrade(impl2Addr);
      expect(await beacon.implementation()).to.equal(impl2Addr);
    });

    it("emits EmergencyUpgrade event", async function () {
      const { beacon, impl2Addr, council } = await deployBeaconFixture();

      await expect(beacon.connect(council).emergencyUpgrade(impl2Addr))
        .to.emit(beacon, "EmergencyUpgrade")
        .withArgs(impl2Addr);
    });

    it("clears pending timelocked upgrade", async function () {
      const { beacon, implAddr, impl2Addr, owner, council } = await deployBeaconFixture();

      // Schedule a standard upgrade
      await beacon.connect(owner).scheduleUpgrade(impl2Addr);
      expect(await beacon.pendingImplementation()).to.equal(impl2Addr);

      // Deploy a third impl for the emergency
      const SovraWalletV1 = await ethers.getContractFactory("SovraWalletV1");
      const impl3 = await SovraWalletV1.deploy();
      await impl3.waitForDeployment();
      const impl3Addr = await impl3.getAddress();

      await beacon.connect(council).emergencyUpgrade(impl3Addr);

      expect(await beacon.implementation()).to.equal(impl3Addr);
      expect(await beacon.pendingImplementation()).to.equal(ethers.ZeroAddress);
      expect(await beacon.activationTime()).to.equal(0);
    });

    it("reverts for non-council caller", async function () {
      const { beacon, impl2Addr, owner, other } = await deployBeaconFixture();

      await expect(
        beacon.connect(owner).emergencyUpgrade(impl2Addr)
      ).to.be.revertedWithCustomError(beacon, "NotSecurityCouncil");

      await expect(
        beacon.connect(other).emergencyUpgrade(impl2Addr)
      ).to.be.revertedWithCustomError(beacon, "NotSecurityCouncil");
    });

    it("reverts for zero address", async function () {
      const { beacon, council } = await deployBeaconFixture();
      await expect(
        beacon.connect(council).emergencyUpgrade(ethers.ZeroAddress)
      ).to.be.revertedWithCustomError(beacon, "InvalidImplementation");
    });

    it("reverts for non-contract address", async function () {
      const { beacon, council, other } = await deployBeaconFixture();
      await expect(
        beacon.connect(council).emergencyUpgrade(other.address)
      ).to.be.revertedWithCustomError(beacon, "NotAContract");
    });
  });

  // ─── Security Council Management ──────────────────────

  describe("setSecurityCouncil", function () {
    it("updates security council", async function () {
      const { beacon, owner, other } = await deployBeaconFixture();

      await beacon.connect(owner).setSecurityCouncil(other.address);
      expect(await beacon.securityCouncil()).to.equal(other.address);
    });

    it("emits SecurityCouncilUpdated event", async function () {
      const { beacon, owner, council, other } = await deployBeaconFixture();

      await expect(beacon.connect(owner).setSecurityCouncil(other.address))
        .to.emit(beacon, "SecurityCouncilUpdated")
        .withArgs(council.address, other.address);
    });

    it("reverts for non-owner", async function () {
      const { beacon, council, other } = await deployBeaconFixture();
      await expect(
        beacon.connect(other).setSecurityCouncil(council.address)
      ).to.be.revertedWithCustomError(beacon, "OwnableUnauthorizedAccount");
    });

    it("reverts for zero address", async function () {
      const { beacon, owner } = await deployBeaconFixture();
      await expect(
        beacon.connect(owner).setSecurityCouncil(ethers.ZeroAddress)
      ).to.be.revertedWithCustomError(beacon, "InvalidSecurityCouncil");
    });
  });
});
