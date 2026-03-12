import { expect } from "chai";
import { ethers } from "hardhat";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";
import { SovraIssuerRegistryV1, SovraIssuerRegistryV2Mock } from "../../typechain-types";

const DRIVING_LICENCE = ethers.keccak256(
  ethers.toUtf8Bytes("DrivingLicenceCredential")
);
const NATIONAL_ID = ethers.keccak256(
  ethers.toUtf8Bytes("NationalIDCredential")
);
const DIPLOMA = ethers.keccak256(ethers.toUtf8Bytes("DiplomaCredential"));

async function deployRegistry(owner: HardhatEthersSigner) {
  const ImplFactory = await ethers.getContractFactory(
    "SovraIssuerRegistryV1"
  );
  const impl = await ImplFactory.deploy();

  const ProxyFactory = await ethers.getContractFactory("ERC1967Proxy");
  const proxy = await ProxyFactory.deploy(
    await impl.getAddress(),
    impl.interface.encodeFunctionData("initialize", [owner.address])
  );

  const registry = ImplFactory.attach(
    await proxy.getAddress()
  ) as SovraIssuerRegistryV1;

  return { registry, impl, proxy };
}

describe("SovraIssuerRegistryV1", function () {
  let owner: HardhatEthersSigner;
  let other: HardhatEthersSigner;
  let issuer1: HardhatEthersSigner;
  let issuer2: HardhatEthersSigner;
  let registry: SovraIssuerRegistryV1;

  beforeEach(async function () {
    [owner, other, issuer1, issuer2] = await ethers.getSigners();
    ({ registry } = await deployRegistry(owner));
  });

  // ─── Initialization ─────────────────────────────────

  describe("initialize", function () {
    it("sets the owner", async function () {
      expect(await registry.owner()).to.equal(owner.address);
    });

    it("emits OwnershipTransferred on init", async function () {
      const { registry: fresh } = await deployRegistry(other);
      const filter = fresh.filters.OwnershipTransferred;
      const events = await fresh.queryFilter(filter);
      expect(events.length).to.equal(1);
      expect(events[0].args.previousOwner).to.equal(ethers.ZeroAddress);
      expect(events[0].args.newOwner).to.equal(other.address);
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
    it("non-owner cannot registerIssuer", async function () {
      await expect(
        registry.connect(other).registerIssuer(issuer1.address, [])
      ).to.be.revertedWithCustomError(registry, "OwnableUnauthorizedAccount");
    });

    it("non-owner cannot addCredentialTypes", async function () {
      await registry.registerIssuer(issuer1.address, []);
      await expect(
        registry.connect(other).addCredentialTypes(issuer1.address, [DIPLOMA])
      ).to.be.revertedWithCustomError(registry, "OwnableUnauthorizedAccount");
    });

    it("non-owner cannot removeCredentialTypes", async function () {
      await registry.registerIssuer(issuer1.address, [DRIVING_LICENCE]);
      await expect(
        registry
          .connect(other)
          .removeCredentialTypes(issuer1.address, [DRIVING_LICENCE])
      ).to.be.revertedWithCustomError(registry, "OwnableUnauthorizedAccount");
    });

    it("non-owner cannot removeIssuer", async function () {
      await registry.registerIssuer(issuer1.address, []);
      await expect(
        registry.connect(other).removeIssuer(issuer1.address)
      ).to.be.revertedWithCustomError(registry, "OwnableUnauthorizedAccount");
    });

    it("non-owner cannot transferOwnership", async function () {
      await expect(
        registry.connect(other).transferOwnership(other.address)
      ).to.be.revertedWithCustomError(registry, "OwnableUnauthorizedAccount");
    });
  });

  // ─── Ownership ──────────────────────────────────────

  describe("transferOwnership (2-step)", function () {
    it("sets pending owner but does not transfer immediately", async function () {
      await registry.transferOwnership(other.address);
      expect(await registry.owner()).to.equal(owner.address);
      expect(await registry.pendingOwner()).to.equal(other.address);
    });

    it("completes transfer when new owner accepts", async function () {
      await registry.transferOwnership(other.address);
      await expect(registry.connect(other).acceptOwnership())
        .to.emit(registry, "OwnershipTransferred")
        .withArgs(owner.address, other.address);

      expect(await registry.owner()).to.equal(other.address);
      expect(await registry.pendingOwner()).to.equal(ethers.ZeroAddress);

      // New owner can operate
      await registry
        .connect(other)
        .registerIssuer(issuer1.address, [DRIVING_LICENCE]);
      expect(await registry.isRegistered(issuer1.address)).to.be.true;

      // Old owner cannot
      await expect(
        registry.registerIssuer(issuer2.address, [])
      ).to.be.revertedWithCustomError(registry, "OwnableUnauthorizedAccount");
    });

    it("only pending owner can accept", async function () {
      await registry.transferOwnership(other.address);
      await expect(
        registry.connect(issuer1).acceptOwnership()
      ).to.be.revertedWithCustomError(registry, "OwnableUnauthorizedAccount");
    });
  });

  // ─── UUPS Upgrade ──────────────────────────────────

  describe("UUPS upgrade", function () {
    it("owner can upgrade and state is preserved", async function () {
      // Register issuer before upgrade
      await registry.registerIssuer(issuer1.address, [DRIVING_LICENCE]);

      // Deploy V2
      const V2Factory = await ethers.getContractFactory(
        "SovraIssuerRegistryV2Mock"
      );
      const v2Impl = await V2Factory.deploy();

      // Upgrade
      await registry.upgradeToAndCall(await v2Impl.getAddress(), "0x");

      // Attach V2 ABI
      const registryV2 = V2Factory.attach(
        await registry.getAddress()
      ) as SovraIssuerRegistryV2Mock;

      // State preserved
      expect(await registryV2.isRegistered(issuer1.address)).to.be.true;
      expect(await registryV2.isTrusted(issuer1.address, DRIVING_LICENCE)).to
        .be.true;
      expect(await registryV2.owner()).to.equal(owner.address);

      // New functionality works
      expect(await registryV2.version()).to.equal(2n);
    });

    it("non-owner cannot upgrade", async function () {
      const V2Factory = await ethers.getContractFactory(
        "SovraIssuerRegistryV2Mock"
      );
      const v2Impl = await V2Factory.deploy();

      await expect(
        registry
          .connect(other)
          .upgradeToAndCall(await v2Impl.getAddress(), "0x")
      ).to.be.revertedWithCustomError(registry, "OwnableUnauthorizedAccount");
    });
  });
});
