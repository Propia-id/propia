import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";
import { SovraIssuerRegistryV1, SovraIssuerRegistryV2Mock } from "../../typechain-types";

const DRIVING_LICENCE = ethers.keccak256(
  ethers.toUtf8Bytes("DrivingLicenceCredential")
);
const NATIONAL_ID = ethers.keccak256(
  ethers.toUtf8Bytes("NationalIDCredential")
);
const DIPLOMA = ethers.keccak256(ethers.toUtf8Bytes("DiplomaCredential"));

const DEFAULT_ADMIN_ROLE = ethers.ZeroHash;
const ISSUER_MANAGER_ROLE = ethers.keccak256(
  ethers.toUtf8Bytes("ISSUER_MANAGER_ROLE")
);
const UPGRADER_ROLE = ethers.keccak256(
  ethers.toUtf8Bytes("UPGRADER_ROLE")
);

async function deployRegistry(admin: HardhatEthersSigner) {
  const Factory = await ethers.getContractFactory("SovraIssuerRegistryV1");
  const registry = await upgrades.deployProxy(Factory, [admin.address], {
    kind: "uups",
  }) as unknown as SovraIssuerRegistryV1;
  await registry.waitForDeployment();
  return { registry };
}

describe("SovraIssuerRegistryV1", function () {
  let admin: HardhatEthersSigner;
  let manager: HardhatEthersSigner;
  let other: HardhatEthersSigner;
  let issuer1: HardhatEthersSigner;
  let issuer2: HardhatEthersSigner;
  let registry: SovraIssuerRegistryV1;

  beforeEach(async function () {
    [admin, manager, other, issuer1, issuer2] = await ethers.getSigners();
    ({ registry } = await deployRegistry(admin));
  });

  // ─── Initialization ─────────────────────────────────

  describe("initialize", function () {
    it("grants all roles to admin", async function () {
      expect(await registry.hasRole(DEFAULT_ADMIN_ROLE, admin.address)).to.be.true;
      expect(await registry.hasRole(ISSUER_MANAGER_ROLE, admin.address)).to.be.true;
      expect(await registry.hasRole(UPGRADER_ROLE, admin.address)).to.be.true;
    });

    it("emits RoleGranted events on init", async function () {
      const { registry: fresh } = await deployRegistry(other);
      const filter = fresh.filters.RoleGranted;
      const events = await fresh.queryFilter(filter);
      expect(events.length).to.equal(3);
    });

    it("reverts on double initialization", async function () {
      await expect(
        registry.initialize(other.address)
      ).to.be.revertedWithCustomError(registry, "InvalidInitialization");
    });
  });

  // ─── Issuer Management ──────────────────────────────

  describe("registerIssuer", function () {
    it("registers an issuer with credential types", async function () {
      await expect(
        registry.registerIssuer(issuer1.address, [DRIVING_LICENCE, NATIONAL_ID])
      )
        .to.emit(registry, "IssuerRegistered")
        .withArgs(issuer1.address, [DRIVING_LICENCE, NATIONAL_ID]);

      expect(await registry.isRegistered(issuer1.address)).to.be.true;
      expect(await registry.isTrusted(issuer1.address, DRIVING_LICENCE)).to.be
        .true;
      expect(await registry.isTrusted(issuer1.address, NATIONAL_ID)).to.be
        .true;
      expect(await registry.isTrusted(issuer1.address, DIPLOMA)).to.be.false;
    });

    it("adds issuer to issuerList", async function () {
      await registry.registerIssuer(issuer1.address, [DRIVING_LICENCE]);
      expect(await registry.issuerList(0)).to.equal(issuer1.address);
    });

    it("registers credential types as known", async function () {
      await registry.registerIssuer(issuer1.address, [DRIVING_LICENCE]);
      expect(await registry.knownType(DRIVING_LICENCE)).to.be.true;
      expect(await registry.credentialTypes(0)).to.equal(DRIVING_LICENCE);
    });

    it("reverts on duplicate registration", async function () {
      await registry.registerIssuer(issuer1.address, [DRIVING_LICENCE]);
      await expect(
        registry.registerIssuer(issuer1.address, [NATIONAL_ID])
      ).to.be.revertedWithCustomError(registry, "AlreadyRegistered");
    });

    it("allows registration with no credential types", async function () {
      await registry.registerIssuer(issuer1.address, []);
      expect(await registry.isRegistered(issuer1.address)).to.be.true;
    });
  });

  describe("addCredentialTypes", function () {
    beforeEach(async function () {
      await registry.registerIssuer(issuer1.address, [DRIVING_LICENCE]);
    });

    it("adds types to an existing issuer", async function () {
      await expect(
        registry.addCredentialTypes(issuer1.address, [NATIONAL_ID, DIPLOMA])
      )
        .to.emit(registry, "IssuerTypesAdded")
        .withArgs(issuer1.address, [NATIONAL_ID, DIPLOMA]);

      expect(await registry.isTrusted(issuer1.address, NATIONAL_ID)).to.be
        .true;
      expect(await registry.isTrusted(issuer1.address, DIPLOMA)).to.be.true;
    });

    it("reverts if issuer not registered", async function () {
      await expect(
        registry.addCredentialTypes(issuer2.address, [DIPLOMA])
      ).to.be.revertedWithCustomError(registry, "IssuerNotRegistered");
    });
  });

  describe("removeCredentialTypes", function () {
    beforeEach(async function () {
      await registry.registerIssuer(issuer1.address, [
        DRIVING_LICENCE,
        NATIONAL_ID,
      ]);
    });

    it("removes specific types from an issuer", async function () {
      await expect(
        registry.removeCredentialTypes(issuer1.address, [DRIVING_LICENCE])
      )
        .to.emit(registry, "IssuerTypesRemoved")
        .withArgs(issuer1.address, [DRIVING_LICENCE]);

      expect(await registry.isTrusted(issuer1.address, DRIVING_LICENCE)).to.be
        .false;
      expect(await registry.isTrusted(issuer1.address, NATIONAL_ID)).to.be
        .true;
    });

    it("reverts if issuer not registered", async function () {
      await expect(
        registry.removeCredentialTypes(issuer2.address, [DRIVING_LICENCE])
      ).to.be.revertedWithCustomError(registry, "IssuerNotRegistered");
    });
  });

  describe("removeIssuer", function () {
    beforeEach(async function () {
      await registry.registerIssuer(issuer1.address, [DRIVING_LICENCE]);
    });

    it("removes an issuer", async function () {
      await expect(registry.removeIssuer(issuer1.address))
        .to.emit(registry, "IssuerRemoved")
        .withArgs(issuer1.address);

      expect(await registry.isRegistered(issuer1.address)).to.be.false;
      expect(await registry.isTrusted(issuer1.address, DRIVING_LICENCE)).to.be
        .false;
    });

    it("reverts if not registered", async function () {
      await expect(
        registry.removeIssuer(issuer2.address)
      ).to.be.revertedWithCustomError(registry, "IssuerNotRegistered");
    });

    it("removes issuer from issuerList", async function () {
      await registry.removeIssuer(issuer1.address);
      await expect(registry.issuerList(0)).to.be.reverted;
    });

    it("swap-and-pop preserves remaining issuers", async function () {
      await registry.registerIssuer(issuer2.address, [NATIONAL_ID]);

      // Remove first issuer
      await registry.removeIssuer(issuer1.address);

      // Second issuer should now be at index 0
      expect(await registry.issuerList(0)).to.equal(issuer2.address);
      await expect(registry.issuerList(1)).to.be.reverted;
    });

    it("allows re-registration without duplicate in issuerList", async function () {
      await registry.removeIssuer(issuer1.address);
      await registry.registerIssuer(issuer1.address, [NATIONAL_ID]);

      // Should have exactly one entry
      expect(await registry.issuerList(0)).to.equal(issuer1.address);
      await expect(registry.issuerList(1)).to.be.reverted;
    });
  });

  // ─── Queries ────────────────────────────────────────

  describe("queries", function () {
    it("isTrusted returns false for unregistered issuer", async function () {
      expect(await registry.isTrusted(issuer1.address, DRIVING_LICENCE)).to.be
        .false;
    });

    it("isRegistered returns false for unknown address", async function () {
      expect(await registry.isRegistered(issuer1.address)).to.be.false;
    });

    it("credential types are deduplicated across issuers", async function () {
      await registry.registerIssuer(issuer1.address, [DRIVING_LICENCE]);
      await registry.registerIssuer(issuer2.address, [DRIVING_LICENCE]);
      // Only one entry in credentialTypes
      expect(await registry.credentialTypes(0)).to.equal(DRIVING_LICENCE);
      await expect(registry.credentialTypes(1)).to.be.reverted;
    });
  });

  // ─── Access Control ─────────────────────────────────

  describe("access control", function () {
    it("account without ISSUER_MANAGER_ROLE cannot registerIssuer", async function () {
      await expect(
        registry.connect(other).registerIssuer(issuer1.address, [])
      ).to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount");
    });

    it("account without ISSUER_MANAGER_ROLE cannot addCredentialTypes", async function () {
      await registry.registerIssuer(issuer1.address, []);
      await expect(
        registry.connect(other).addCredentialTypes(issuer1.address, [DIPLOMA])
      ).to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount");
    });

    it("account without ISSUER_MANAGER_ROLE cannot removeCredentialTypes", async function () {
      await registry.registerIssuer(issuer1.address, [DRIVING_LICENCE]);
      await expect(
        registry
          .connect(other)
          .removeCredentialTypes(issuer1.address, [DRIVING_LICENCE])
      ).to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount");
    });

    it("account without ISSUER_MANAGER_ROLE cannot removeIssuer", async function () {
      await registry.registerIssuer(issuer1.address, []);
      await expect(
        registry.connect(other).removeIssuer(issuer1.address)
      ).to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount");
    });

    it("account without UPGRADER_ROLE cannot upgrade", async function () {
      const V2Factory = await ethers.getContractFactory(
        "SovraIssuerRegistryV2Mock"
      );
      const v2Impl = await V2Factory.deploy();

      await expect(
        registry
          .connect(other)
          .upgradeToAndCall(await v2Impl.getAddress(), "0x")
      ).to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount");
    });
  });

  // ─── Role Management ───────────────────────────────

  describe("role management", function () {
    it("admin can grant ISSUER_MANAGER_ROLE to another account", async function () {
      await registry.grantRole(ISSUER_MANAGER_ROLE, manager.address);
      expect(await registry.hasRole(ISSUER_MANAGER_ROLE, manager.address)).to.be.true;

      // New manager can operate
      await registry
        .connect(manager)
        .registerIssuer(issuer1.address, [DRIVING_LICENCE]);
      expect(await registry.isRegistered(issuer1.address)).to.be.true;
    });

    it("admin can revoke ISSUER_MANAGER_ROLE", async function () {
      await registry.grantRole(ISSUER_MANAGER_ROLE, manager.address);
      await registry.revokeRole(ISSUER_MANAGER_ROLE, manager.address);

      await expect(
        registry.connect(manager).registerIssuer(issuer1.address, [])
      ).to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount");
    });

    it("non-admin cannot grant roles", async function () {
      await expect(
        registry.connect(other).grantRole(ISSUER_MANAGER_ROLE, other.address)
      ).to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount");
    });

    it("account can renounce its own role", async function () {
      await registry.grantRole(ISSUER_MANAGER_ROLE, manager.address);
      await registry.connect(manager).renounceRole(ISSUER_MANAGER_ROLE, manager.address);
      expect(await registry.hasRole(ISSUER_MANAGER_ROLE, manager.address)).to.be.false;
    });

    it("UPGRADER_ROLE is separate from ISSUER_MANAGER_ROLE", async function () {
      // Grant only ISSUER_MANAGER_ROLE
      await registry.grantRole(ISSUER_MANAGER_ROLE, manager.address);

      // Manager can manage issuers
      await registry.connect(manager).registerIssuer(issuer1.address, [DRIVING_LICENCE]);

      // But cannot upgrade
      const V2Factory = await ethers.getContractFactory(
        "SovraIssuerRegistryV2Mock"
      );
      const v2Impl = await V2Factory.deploy();

      await expect(
        registry
          .connect(manager)
          .upgradeToAndCall(await v2Impl.getAddress(), "0x")
      ).to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount");
    });
  });

  // ─── UUPS Upgrade ──────────────────────────────────

  describe("UUPS upgrade", function () {
    it("upgrader can upgrade and state is preserved", async function () {
      // Register issuer before upgrade
      await registry.registerIssuer(issuer1.address, [DRIVING_LICENCE]);

      // Upgrade via plugin (validates storage layout compatibility)
      const V2Factory = await ethers.getContractFactory(
        "SovraIssuerRegistryV2Mock"
      );
      const registryV2 = await upgrades.upgradeProxy(
        await registry.getAddress(),
        V2Factory
      ) as unknown as SovraIssuerRegistryV2Mock;

      // State preserved
      expect(await registryV2.isRegistered(issuer1.address)).to.be.true;
      expect(await registryV2.isTrusted(issuer1.address, DRIVING_LICENCE)).to
        .be.true;
      expect(await registryV2.hasRole(DEFAULT_ADMIN_ROLE, admin.address)).to.be.true;

      // New functionality works
      expect(await registryV2.version()).to.equal(2n);
    });
  });
});
