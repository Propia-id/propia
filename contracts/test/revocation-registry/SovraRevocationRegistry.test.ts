import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";
import {
  SovraRevocationRegistryV1,
  SovraRevocationRegistryV2Mock,
  SovraIssuerRegistryV1,
} from "../../typechain-types";

const DRIVING_LICENCE = ethers.keccak256(
  ethers.toUtf8Bytes("DrivingLicenceCredential")
);

const DEFAULT_ADMIN_ROLE = ethers.ZeroHash;
const STATUS_MANAGER_ROLE = ethers.keccak256(
  ethers.toUtf8Bytes("STATUS_MANAGER_ROLE")
);
const UPGRADER_ROLE = ethers.keccak256(
  ethers.toUtf8Bytes("UPGRADER_ROLE")
);
const ISSUER_MANAGER_ROLE = ethers.keccak256(
  ethers.toUtf8Bytes("ISSUER_MANAGER_ROLE")
);

const REVOCATION = 0;
const SUSPENSION = 1;

async function deployFixture(admin: HardhatEthersSigner) {
  // Deploy Issuer Registry (needed for cross-contract validation)
  const IssuerFactory = await ethers.getContractFactory("SovraIssuerRegistryV1");
  const issuerRegistry = await upgrades.deployProxy(IssuerFactory, [admin.address], {
    kind: "uups",
  }) as unknown as SovraIssuerRegistryV1;
  await issuerRegistry.waitForDeployment();

  // Deploy Revocation Registry
  const RevocationFactory = await ethers.getContractFactory("SovraRevocationRegistryV1");
  const registry = await upgrades.deployProxy(
    RevocationFactory,
    [admin.address, await issuerRegistry.getAddress()],
    { kind: "uups" }
  ) as unknown as SovraRevocationRegistryV1;
  await registry.waitForDeployment();

  return { registry, issuerRegistry };
}

describe("SovraRevocationRegistryV1", function () {
  let admin: HardhatEthersSigner;
  let other: HardhatEthersSigner;
  let issuer1: HardhatEthersSigner;
  let issuer2: HardhatEthersSigner;
  let registry: SovraRevocationRegistryV1;
  let issuerRegistry: SovraIssuerRegistryV1;

  beforeEach(async function () {
    [admin, other, issuer1, issuer2] = await ethers.getSigners();
    ({ registry, issuerRegistry } = await deployFixture(admin));
    // Register issuer1 in the Issuer Registry so it can have bitmaps
    await issuerRegistry.registerIssuer(issuer1.address, [DRIVING_LICENCE]);
  });

  // ─── Initialization ─────────────────────────────────

  describe("initialize", function () {
    it("grants all roles to admin", async function () {
      expect(await registry.hasRole(DEFAULT_ADMIN_ROLE, admin.address)).to.be.true;
      expect(await registry.hasRole(STATUS_MANAGER_ROLE, admin.address)).to.be.true;
      expect(await registry.hasRole(UPGRADER_ROLE, admin.address)).to.be.true;
    });

    it("stores the issuer registry address", async function () {
      expect(await registry.issuerRegistry()).to.equal(
        await issuerRegistry.getAddress()
      );
    });

    it("reverts on double initialization", async function () {
      await expect(
        registry.initialize(other.address, await issuerRegistry.getAddress())
      ).to.be.revertedWithCustomError(registry, "InvalidInitialization");
    });
  });

  // ─── Bitmap Initialization ──────────────────────────

  describe("initializeBitmap", function () {
    it("initializes a revocation bitmap for a registered issuer", async function () {
      await expect(registry.initializeBitmap(issuer1.address, REVOCATION))
        .to.emit(registry, "BitmapInitialized")
        .withArgs(issuer1.address, REVOCATION);
    });

    it("initializes a suspension bitmap for a registered issuer", async function () {
      await expect(registry.initializeBitmap(issuer1.address, SUSPENSION))
        .to.emit(registry, "BitmapInitialized")
        .withArgs(issuer1.address, SUSPENSION);
    });

    it("reverts on double initialization", async function () {
      await registry.initializeBitmap(issuer1.address, REVOCATION);
      await expect(
        registry.initializeBitmap(issuer1.address, REVOCATION)
      ).to.be.revertedWithCustomError(registry, "BitmapAlreadyInitialized");
    });

    it("allows separate initialization for revocation and suspension", async function () {
      await registry.initializeBitmap(issuer1.address, REVOCATION);
      await expect(registry.initializeBitmap(issuer1.address, SUSPENSION))
        .to.emit(registry, "BitmapInitialized")
        .withArgs(issuer1.address, SUSPENSION);
    });

    it("reverts for unregistered issuer", async function () {
      await expect(
        registry.initializeBitmap(issuer2.address, REVOCATION)
      ).to.be.revertedWithCustomError(registry, "IssuerNotRegistered");
    });

    it("reverts for invalid purpose", async function () {
      await expect(
        registry.initializeBitmap(issuer1.address, 2)
      ).to.be.revertedWithCustomError(registry, "InvalidPurpose");
    });
  });

  // ─── setStatus ──────────────────────────────────────

  describe("setStatus", function () {
    beforeEach(async function () {
      await registry.initializeBitmap(issuer1.address, REVOCATION);
      await registry.initializeBitmap(issuer1.address, SUSPENSION);
    });

    it("sets a revocation bit and emits StatusChanged", async function () {
      await expect(registry.setStatus(issuer1.address, REVOCATION, 42))
        .to.emit(registry, "StatusChanged")
        .withArgs(issuer1.address, REVOCATION, 42, true);

      expect(await registry.getStatus(issuer1.address, REVOCATION, 42)).to.be.true;
    });

    it("sets a suspension bit", async function () {
      await registry.setStatus(issuer1.address, SUSPENSION, 100);
      expect(await registry.getStatus(issuer1.address, SUSPENSION, 100)).to.be.true;
    });

    it("setting an already-set bit is idempotent", async function () {
      await registry.setStatus(issuer1.address, REVOCATION, 42);
      await registry.setStatus(issuer1.address, REVOCATION, 42);
      expect(await registry.getStatus(issuer1.address, REVOCATION, 42)).to.be.true;
    });

    it("extends the bitmap array for high indices", async function () {
      // Index 131071 = last bit in slot 511 (131071 / 256 = 511, 131071 % 256 = 255)
      await registry.setStatus(issuer1.address, REVOCATION, 131071);
      expect(await registry.getStatus(issuer1.address, REVOCATION, 131071)).to.be.true;
    });

    it("handles index 0 correctly", async function () {
      await registry.setStatus(issuer1.address, REVOCATION, 0);
      expect(await registry.getStatus(issuer1.address, REVOCATION, 0)).to.be.true;
      // Adjacent bits remain unset
      expect(await registry.getStatus(issuer1.address, REVOCATION, 1)).to.be.false;
    });

    it("handles multiple bits in the same slot", async function () {
      await registry.setStatus(issuer1.address, REVOCATION, 0);
      await registry.setStatus(issuer1.address, REVOCATION, 1);
      await registry.setStatus(issuer1.address, REVOCATION, 255);
      expect(await registry.getStatus(issuer1.address, REVOCATION, 0)).to.be.true;
      expect(await registry.getStatus(issuer1.address, REVOCATION, 1)).to.be.true;
      expect(await registry.getStatus(issuer1.address, REVOCATION, 255)).to.be.true;
      expect(await registry.getStatus(issuer1.address, REVOCATION, 128)).to.be.false;
    });

    it("reverts if bitmap not initialized", async function () {
      await issuerRegistry.registerIssuer(issuer2.address, [DRIVING_LICENCE]);
      await expect(
        registry.setStatus(issuer2.address, REVOCATION, 0)
      ).to.be.revertedWithCustomError(registry, "BitmapNotInitialized");
    });
  });

  // ─── clearStatus ────────────────────────────────────

  describe("clearStatus", function () {
    beforeEach(async function () {
      await registry.initializeBitmap(issuer1.address, REVOCATION);
      await registry.initializeBitmap(issuer1.address, SUSPENSION);
    });

    it("clears a suspension bit", async function () {
      await registry.setStatus(issuer1.address, SUSPENSION, 50);
      expect(await registry.getStatus(issuer1.address, SUSPENSION, 50)).to.be.true;

      await expect(registry.clearStatus(issuer1.address, SUSPENSION, 50))
        .to.emit(registry, "StatusChanged")
        .withArgs(issuer1.address, SUSPENSION, 50, false);

      expect(await registry.getStatus(issuer1.address, SUSPENSION, 50)).to.be.false;
    });

    it("reverts with CannotUnrevoke for revocation purpose", async function () {
      await registry.setStatus(issuer1.address, REVOCATION, 50);
      await expect(
        registry.clearStatus(issuer1.address, REVOCATION, 50)
      ).to.be.revertedWithCustomError(registry, "CannotUnrevoke");
    });

    it("clearing an already-cleared bit is a no-op", async function () {
      await registry.clearStatus(issuer1.address, SUSPENSION, 999);
      expect(await registry.getStatus(issuer1.address, SUSPENSION, 999)).to.be.false;
    });

    it("clearing does not affect adjacent bits", async function () {
      await registry.setStatus(issuer1.address, SUSPENSION, 10);
      await registry.setStatus(issuer1.address, SUSPENSION, 11);
      await registry.clearStatus(issuer1.address, SUSPENSION, 10);
      expect(await registry.getStatus(issuer1.address, SUSPENSION, 10)).to.be.false;
      expect(await registry.getStatus(issuer1.address, SUSPENSION, 11)).to.be.true;
    });
  });

  // ─── batchSetStatus ─────────────────────────────────

  describe("batchSetStatus", function () {
    beforeEach(async function () {
      await registry.initializeBitmap(issuer1.address, REVOCATION);
    });

    it("sets multiple bits in one transaction", async function () {
      const indices = [0, 42, 255, 256, 1000];
      const tx = registry.batchSetStatus(issuer1.address, REVOCATION, indices);

      for (const idx of indices) {
        await expect(tx)
          .to.emit(registry, "StatusChanged")
          .withArgs(issuer1.address, REVOCATION, idx, true);
      }

      for (const idx of indices) {
        expect(await registry.getStatus(issuer1.address, REVOCATION, idx)).to.be.true;
      }
    });

    it("handles empty array", async function () {
      await registry.batchSetStatus(issuer1.address, REVOCATION, []);
      // No revert, no events
    });

    it("reverts if bitmap not initialized", async function () {
      await issuerRegistry.registerIssuer(issuer2.address, [DRIVING_LICENCE]);
      await expect(
        registry.batchSetStatus(issuer2.address, REVOCATION, [0, 1])
      ).to.be.revertedWithCustomError(registry, "BitmapNotInitialized");
    });
  });

  // ─── getStatus ──────────────────────────────────────

  describe("getStatus", function () {
    it("returns false for unset bits", async function () {
      await registry.initializeBitmap(issuer1.address, REVOCATION);
      expect(await registry.getStatus(issuer1.address, REVOCATION, 0)).to.be.false;
      expect(await registry.getStatus(issuer1.address, REVOCATION, 131071)).to.be.false;
    });

    it("returns false for out-of-range indices (beyond allocated slots)", async function () {
      await registry.initializeBitmap(issuer1.address, REVOCATION);
      // No slots allocated yet — any index returns false
      expect(await registry.getStatus(issuer1.address, REVOCATION, 999999)).to.be.false;
    });

    it("returns false for uninitialized bitmap", async function () {
      // getStatus is a view — it doesn't revert, just returns false
      expect(await registry.getStatus(issuer2.address, REVOCATION, 0)).to.be.false;
    });
  });

  // ─── getBitmap ──────────────────────────────────────

  describe("getBitmap", function () {
    beforeEach(async function () {
      await registry.initializeBitmap(issuer1.address, REVOCATION);
    });

    it("returns at least 512 slots (131,072 bits)", async function () {
      const bitmap = await registry.getBitmap(issuer1.address, REVOCATION);
      expect(bitmap.length).to.equal(512);
    });

    it("returns all zeros for a fresh bitmap", async function () {
      const bitmap = await registry.getBitmap(issuer1.address, REVOCATION);
      for (const word of bitmap) {
        expect(word).to.equal(0n);
      }
    });

    it("reflects set bits in the returned bitmap", async function () {
      await registry.setStatus(issuer1.address, REVOCATION, 0);
      await registry.setStatus(issuer1.address, REVOCATION, 256);

      const bitmap = await registry.getBitmap(issuer1.address, REVOCATION);
      // Bit 0 of slot 0 should be set
      expect(bitmap[0]).to.equal(1n);
      // Bit 0 of slot 1 should be set
      expect(bitmap[1]).to.equal(1n);
      // Other slots should be 0
      expect(bitmap[2]).to.equal(0n);
    });

    it("pads beyond stored length", async function () {
      // Set only bit 0 — only 1 slot is stored on-chain
      await registry.setStatus(issuer1.address, REVOCATION, 0);
      const bitmap = await registry.getBitmap(issuer1.address, REVOCATION);
      expect(bitmap.length).to.equal(512);
      expect(bitmap[0]).to.equal(1n);
      expect(bitmap[511]).to.equal(0n);
    });

    it("returns more than 512 slots if issuer has high indices", async function () {
      // Index 131072 → slot 512 (beyond the minimum)
      await registry.setStatus(issuer1.address, REVOCATION, 131072);
      const bitmap = await registry.getBitmap(issuer1.address, REVOCATION);
      expect(bitmap.length).to.equal(513);
      expect(bitmap[512]).to.equal(1n);
    });
  });

  // ─── Access Control ─────────────────────────────────

  describe("access control", function () {
    it("account without STATUS_MANAGER_ROLE cannot initializeBitmap", async function () {
      await expect(
        registry.connect(other).initializeBitmap(issuer1.address, REVOCATION)
      ).to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount");
    });

    it("account without STATUS_MANAGER_ROLE cannot setStatus", async function () {
      await registry.initializeBitmap(issuer1.address, REVOCATION);
      await expect(
        registry.connect(other).setStatus(issuer1.address, REVOCATION, 0)
      ).to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount");
    });

    it("account without STATUS_MANAGER_ROLE cannot clearStatus", async function () {
      await registry.initializeBitmap(issuer1.address, SUSPENSION);
      await expect(
        registry.connect(other).clearStatus(issuer1.address, SUSPENSION, 0)
      ).to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount");
    });

    it("account without STATUS_MANAGER_ROLE cannot batchSetStatus", async function () {
      await registry.initializeBitmap(issuer1.address, REVOCATION);
      await expect(
        registry.connect(other).batchSetStatus(issuer1.address, REVOCATION, [0])
      ).to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount");
    });

    it("account without UPGRADER_ROLE cannot upgrade", async function () {
      const V2Factory = await ethers.getContractFactory("SovraRevocationRegistryV2Mock");
      const v2Impl = await V2Factory.deploy();
      await expect(
        registry.connect(other).upgradeToAndCall(await v2Impl.getAddress(), "0x")
      ).to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount");
    });

    it("admin can grant STATUS_MANAGER_ROLE to another account", async function () {
      await registry.grantRole(STATUS_MANAGER_ROLE, other.address);
      expect(await registry.hasRole(STATUS_MANAGER_ROLE, other.address)).to.be.true;

      await registry.initializeBitmap(issuer1.address, REVOCATION);
      await registry.connect(other).setStatus(issuer1.address, REVOCATION, 0);
      expect(await registry.getStatus(issuer1.address, REVOCATION, 0)).to.be.true;
    });
  });

  // ─── UUPS Upgrade ──────────────────────────────────

  describe("UUPS upgrade", function () {
    it("upgrader can upgrade and state is preserved", async function () {
      // Set some state before upgrade
      await registry.initializeBitmap(issuer1.address, REVOCATION);
      await registry.setStatus(issuer1.address, REVOCATION, 42);

      // Upgrade
      const V2Factory = await ethers.getContractFactory("SovraRevocationRegistryV2Mock");
      const registryV2 = await upgrades.upgradeProxy(
        await registry.getAddress(),
        V2Factory
      ) as unknown as SovraRevocationRegistryV2Mock;

      // State preserved
      expect(await registryV2.getStatus(issuer1.address, REVOCATION, 42)).to.be.true;
      expect(await registryV2.hasRole(DEFAULT_ADMIN_ROLE, admin.address)).to.be.true;
      expect(await registryV2.issuerRegistry()).to.equal(
        await issuerRegistry.getAddress()
      );

      // New functionality works
      expect(await registryV2.version()).to.equal(2n);
    });
  });
});
