import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";
import { NetworkRoleConfig, parseChainConfig, roleId } from "../scripts/chain-config";
import {
  applyRoleConfig,
  grantConfiguredRoles,
  Registries,
  renounceDeployerRoles,
  verifyRoles,
} from "../scripts/roles";
import { toRegistries } from "../scripts/registries";
import {
  SovraDIDRegistryV1,
  SovraIssuerRegistryV1,
  SovraRevocationRegistryV1,
} from "../typechain-types";

const DEFAULT_ADMIN_ROLE = roleId("DEFAULT_ADMIN_ROLE");
const DID_MANAGER_ROLE = roleId("DID_MANAGER_ROLE");
const ISSUER_MANAGER_ROLE = roleId("ISSUER_MANAGER_ROLE");
const STATUS_MANAGER_ROLE = roleId("STATUS_MANAGER_ROLE");
const UPGRADER_ROLE = roleId("UPGRADER_ROLE");

interface Deployed {
  did: SovraDIDRegistryV1;
  issuer: SovraIssuerRegistryV1;
  revocation: SovraRevocationRegistryV1;
  registries: Registries;
}

/// Deploys the three registries exactly as scripts/deploy.ts does: the deployer
/// is the bootstrap admin of each one.
async function deployRegistries(deployer: HardhatEthersSigner): Promise<Deployed> {
  const DID = await ethers.getContractFactory("SovraDIDRegistryV1", deployer);
  const did = (await upgrades.deployProxy(DID, [deployer.address], {
    kind: "uups",
  })) as unknown as SovraDIDRegistryV1;
  await did.waitForDeployment();

  const Issuer = await ethers.getContractFactory("SovraIssuerRegistryV1", deployer);
  const issuer = (await upgrades.deployProxy(Issuer, [deployer.address], {
    kind: "uups",
  })) as unknown as SovraIssuerRegistryV1;
  await issuer.waitForDeployment();

  const Revocation = await ethers.getContractFactory("SovraRevocationRegistryV1", deployer);
  const revocation = (await upgrades.deployProxy(
    Revocation,
    [deployer.address, await issuer.getAddress()],
    { kind: "uups" }
  )) as unknown as SovraRevocationRegistryV1;
  await revocation.waitForDeployment();

  const registries = toRegistries({
    SovraDIDRegistryV1: did,
    SovraIssuerRegistryV1: issuer,
    SovraRevocationRegistryV1: revocation,
  });

  return { did, issuer, revocation, registries };
}

/// Builds a config through the real validator, so the tests exercise the same
/// path a deploy does.
function buildConfig(opts: {
  admin: string;
  upgrader: string;
  managers: string[];
  renounceDeployer: boolean;
  beaconOwner?: string;
  securityCouncil?: string;
}): NetworkRoleConfig {
  const { admin, upgrader, managers, renounceDeployer } = opts;
  return parseChainConfig(
    {
      testnet: {
        beaconOwner: opts.beaconOwner ?? admin,
        securityCouncil: opts.securityCouncil ?? admin,
        renounceDeployer,
        roles: {
          SovraDIDRegistryV1: {
            DEFAULT_ADMIN_ROLE: [admin],
            DID_MANAGER_ROLE: managers,
            UPGRADER_ROLE: [upgrader],
          },
          SovraIssuerRegistryV1: {
            DEFAULT_ADMIN_ROLE: [admin],
            ISSUER_MANAGER_ROLE: managers,
            UPGRADER_ROLE: [upgrader],
          },
          SovraRevocationRegistryV1: {
            DEFAULT_ADMIN_ROLE: [admin],
            STATUS_MANAGER_ROLE: managers,
            UPGRADER_ROLE: [upgrader],
          },
        },
      },
    },
    "testnet"
  );
}

describe("deploy roles", function () {
  let deployer: HardhatEthersSigner;
  let admin: HardhatEthersSigner;
  let upgrader: HardhatEthersSigner;
  let backend: HardhatEthersSigner;
  let relayer: HardhatEthersSigner;
  let deployed: Deployed;

  beforeEach(async function () {
    [deployer, admin, upgrader, backend, relayer] = await ethers.getSigners();
    deployed = await deployRegistries(deployer);
  });

  // ─── Grant ──────────────────────────────────────────

  describe("grantConfiguredRoles", function () {
    it("grants every configured role on every registry", async function () {
      const config = buildConfig({
        admin: admin.address,
        upgrader: upgrader.address,
        managers: [backend.address],
        renounceDeployer: false,
      });

      await grantConfiguredRoles(deployed.registries, config);

      const { did, issuer, revocation } = deployed;
      expect(await did.hasRole(DEFAULT_ADMIN_ROLE, admin.address)).to.be.true;
      expect(await did.hasRole(DID_MANAGER_ROLE, backend.address)).to.be.true;
      expect(await did.hasRole(UPGRADER_ROLE, upgrader.address)).to.be.true;
      expect(await issuer.hasRole(DEFAULT_ADMIN_ROLE, admin.address)).to.be.true;
      expect(await issuer.hasRole(ISSUER_MANAGER_ROLE, backend.address)).to.be.true;
      expect(await issuer.hasRole(UPGRADER_ROLE, upgrader.address)).to.be.true;
      expect(await revocation.hasRole(DEFAULT_ADMIN_ROLE, admin.address)).to.be.true;
      expect(await revocation.hasRole(STATUS_MANAGER_ROLE, backend.address)).to.be.true;
      expect(await revocation.hasRole(UPGRADER_ROLE, upgrader.address)).to.be.true;
    });

    it("grants nothing beyond what is configured", async function () {
      const config = buildConfig({
        admin: admin.address,
        upgrader: upgrader.address,
        managers: [backend.address],
        renounceDeployer: false,
      });

      await grantConfiguredRoles(deployed.registries, config);

      const { did, issuer } = deployed;
      expect(await did.hasRole(DID_MANAGER_ROLE, admin.address)).to.be.false;
      expect(await did.hasRole(DEFAULT_ADMIN_ROLE, upgrader.address)).to.be.false;
      expect(await did.hasRole(UPGRADER_ROLE, backend.address)).to.be.false;
      expect(await issuer.hasRole(ISSUER_MANAGER_ROLE, relayer.address)).to.be.false;
    });

    it("supports several holders of one manager role", async function () {
      const config = buildConfig({
        admin: admin.address,
        upgrader: upgrader.address,
        managers: [backend.address, relayer.address],
        renounceDeployer: false,
      });

      await grantConfiguredRoles(deployed.registries, config);

      expect(await deployed.did.hasRole(DID_MANAGER_ROLE, backend.address)).to.be.true;
      expect(await deployed.did.hasRole(DID_MANAGER_ROLE, relayer.address)).to.be.true;
    });

    it("reports each grant", async function () {
      const config = buildConfig({
        admin: admin.address,
        upgrader: upgrader.address,
        managers: [backend.address],
        renounceDeployer: false,
      });

      const grants = await grantConfiguredRoles(deployed.registries, config);

      expect(grants).to.have.lengthOf(9);
      expect(grants.every((g) => !g.alreadyHeld)).to.be.true;
      expect(grants.filter((g) => g.contract === "SovraDIDRegistryV1")).to.have.lengthOf(3);
    });

    it("sends no transaction for a role the account already holds", async function () {
      // The deployer already holds all three roles from initialize().
      const config = buildConfig({
        admin: deployer.address,
        upgrader: deployer.address,
        managers: [deployer.address],
        renounceDeployer: false,
      });
      const before = await ethers.provider.getTransactionCount(deployer.address);

      const grants = await grantConfiguredRoles(deployed.registries, config);

      expect(grants.every((g) => g.alreadyHeld)).to.be.true;
      expect(await ethers.provider.getTransactionCount(deployer.address)).to.equal(before);
    });
  });

  // ─── Renounce ───────────────────────────────────────

  describe("renounceDeployerRoles", function () {
    it("drops all nine deployer roles and leaves the configured holders alone", async function () {
      const config = buildConfig({
        admin: admin.address,
        upgrader: upgrader.address,
        managers: [backend.address],
        renounceDeployer: true,
      });
      await grantConfiguredRoles(deployed.registries, config);

      const renounced = await renounceDeployerRoles(deployed.registries, config, deployer.address);

      expect(renounced).to.have.lengthOf(9);
      const { did, issuer, revocation } = deployed;
      for (const [registry, manager] of [
        [did, DID_MANAGER_ROLE],
        [issuer, ISSUER_MANAGER_ROLE],
        [revocation, STATUS_MANAGER_ROLE],
      ] as const) {
        expect(await registry.hasRole(DEFAULT_ADMIN_ROLE, deployer.address)).to.be.false;
        expect(await registry.hasRole(manager, deployer.address)).to.be.false;
        expect(await registry.hasRole(UPGRADER_ROLE, deployer.address)).to.be.false;
      }
      expect(await did.hasRole(DEFAULT_ADMIN_ROLE, admin.address)).to.be.true;
      expect(await did.hasRole(DID_MANAGER_ROLE, backend.address)).to.be.true;
      expect(await did.hasRole(UPGRADER_ROLE, upgrader.address)).to.be.true;
    });

    it("leaves the new admin able to keep managing roles afterwards", async function () {
      const config = buildConfig({
        admin: admin.address,
        upgrader: upgrader.address,
        managers: [backend.address],
        renounceDeployer: true,
      });
      await grantConfiguredRoles(deployed.registries, config);
      await renounceDeployerRoles(deployed.registries, config, deployer.address);

      await deployed.did.connect(admin).grantRole(DID_MANAGER_ROLE, relayer.address);
      expect(await deployed.did.hasRole(DID_MANAGER_ROLE, relayer.address)).to.be.true;

      await expect(
        deployed.did.connect(deployer).grantRole(DID_MANAGER_ROLE, deployer.address)
      ).to.be.revertedWithCustomError(deployed.did, "AccessControlUnauthorizedAccount");
    });

    it("refuses to renounce when no configured admin holds the role on-chain", async function () {
      // Grants were never applied, so `admin` has nothing.
      const config = buildConfig({
        admin: admin.address,
        upgrader: upgrader.address,
        managers: [backend.address],
        renounceDeployer: true,
      });

      await expect(
        renounceDeployerRoles(deployed.registries, config, deployer.address)
      ).to.be.rejectedWith("refusing to renounce SovraDIDRegistryV1.DEFAULT_ADMIN_ROLE");

      // Nothing was given up.
      expect(await deployed.did.hasRole(DEFAULT_ADMIN_ROLE, deployer.address)).to.be.true;
      expect(await deployed.did.hasRole(UPGRADER_ROLE, deployer.address)).to.be.true;
      expect(await deployed.issuer.hasRole(DEFAULT_ADMIN_ROLE, deployer.address)).to.be.true;
    });
  });

  // ─── Sender of view calls ───────────────────────────

  describe("eth_call sender", function () {
    /// Records the view calls as they leave ethers, before hardhat's
    /// SenderProvider would fill in a missing `from`.
    async function recordCalls(run: () => Promise<unknown>) {
      const provider = ethers.provider as unknown as {
        call(tx: { from?: string }): Promise<string>;
      };
      const original = provider.call.bind(provider);
      const calls: Array<{ from?: string }> = [];

      provider.call = async (tx) => {
        calls.push(tx);
        return original(tx);
      };
      try {
        await run();
      } finally {
        provider.call = original;
      }
      return calls;
    }

    it("reads as the zero address, never as the deployer", async function () {
      // ethrex validates the nonce of an eth_call against its `from`, so a read
      // as the deployer fails once that key has sent a transaction.
      const config = buildConfig({
        admin: admin.address,
        upgrader: upgrader.address,
        managers: [backend.address],
        renounceDeployer: true,
      });

      const calls = await recordCalls(() =>
        applyRoleConfig(deployed.registries, config, deployer.address)
      );

      expect(calls).to.not.be.empty;
      expect(calls.every((c) => c.from === ethers.ZeroAddress)).to.be.true;
    });
  });

  // ─── Apply (grant + renounce + verify) ──────────────

  describe("applyRoleConfig", function () {
    it("grants, renounces and verifies in one step", async function () {
      const config = buildConfig({
        admin: admin.address,
        upgrader: upgrader.address,
        managers: [backend.address],
        renounceDeployer: true,
      });

      const { granted, renounced } = await applyRoleConfig(
        deployed.registries,
        config,
        deployer.address
      );

      expect(granted).to.have.lengthOf(9);
      expect(renounced).to.have.lengthOf(9);
      expect(await deployed.did.hasRole(DID_MANAGER_ROLE, backend.address)).to.be.true;
      expect(await deployed.did.hasRole(DEFAULT_ADMIN_ROLE, deployer.address)).to.be.false;
    });

    it("skips the renounce when the config keeps the deployer", async function () {
      const config = buildConfig({
        admin: admin.address,
        upgrader: upgrader.address,
        managers: [backend.address],
        renounceDeployer: false,
      });

      const { renounced } = await applyRoleConfig(deployed.registries, config, deployer.address);

      expect(renounced).to.be.empty;
      expect(await deployed.did.hasRole(DEFAULT_ADMIN_ROLE, deployer.address)).to.be.true;
    });

    it("is idempotent — a second run sends no transaction", async function () {
      const config = buildConfig({
        admin: admin.address,
        upgrader: upgrader.address,
        managers: [backend.address],
        renounceDeployer: false,
      });
      await applyRoleConfig(deployed.registries, config, deployer.address);
      const before = await ethers.provider.getTransactionCount(deployer.address);

      const { granted } = await applyRoleConfig(deployed.registries, config, deployer.address);

      expect(granted.every((g) => g.alreadyHeld)).to.be.true;
      expect(await ethers.provider.getTransactionCount(deployer.address)).to.equal(before);
    });
  });

  // ─── Verification ───────────────────────────────────

  describe("verifyRoles", function () {
    it("passes for a completed handoff", async function () {
      const config = buildConfig({
        admin: admin.address,
        upgrader: upgrader.address,
        managers: [backend.address],
        renounceDeployer: true,
      });
      await grantConfiguredRoles(deployed.registries, config);
      await renounceDeployerRoles(deployed.registries, config, deployer.address);

      await expect(verifyRoles(deployed.registries, config, deployer.address)).to.not.be.rejected;
    });

    it("passes when the deployer keeps its roles by configuration", async function () {
      const config = buildConfig({
        admin: admin.address,
        upgrader: upgrader.address,
        managers: [backend.address],
        renounceDeployer: false,
      });
      await grantConfiguredRoles(deployed.registries, config);

      await expect(verifyRoles(deployed.registries, config, deployer.address)).to.not.be.rejected;
    });

    it("fails when a configured holder is missing its role", async function () {
      const config = buildConfig({
        admin: admin.address,
        upgrader: upgrader.address,
        managers: [backend.address],
        renounceDeployer: true,
      });
      await grantConfiguredRoles(deployed.registries, config);
      await renounceDeployerRoles(deployed.registries, config, deployer.address);
      await deployed.did.connect(admin).revokeRole(DID_MANAGER_ROLE, backend.address);

      await expect(verifyRoles(deployed.registries, config, deployer.address)).to.be.rejectedWith(
        `SovraDIDRegistryV1.DID_MANAGER_ROLE is not held by configured holder ${backend.address}`
      );
    });

    it("fails when the deployer still holds a role after a renouncing deploy", async function () {
      const config = buildConfig({
        admin: admin.address,
        upgrader: upgrader.address,
        managers: [backend.address],
        renounceDeployer: true,
      });
      await grantConfiguredRoles(deployed.registries, config);

      await expect(verifyRoles(deployed.registries, config, deployer.address)).to.be.rejectedWith(
        `SovraDIDRegistryV1.DEFAULT_ADMIN_ROLE is still held by the deployer ${deployer.address}`
      );
    });

    it("fails when the deployer lost a role it was meant to keep", async function () {
      const config = buildConfig({
        admin: admin.address,
        upgrader: upgrader.address,
        managers: [backend.address],
        renounceDeployer: false,
      });
      await grantConfiguredRoles(deployed.registries, config);
      await deployed.did.connect(deployer).renounceRole(UPGRADER_ROLE, deployer.address);

      await expect(verifyRoles(deployed.registries, config, deployer.address)).to.be.rejectedWith(
        "SovraDIDRegistryV1.UPGRADER_ROLE is not held by the deployer"
      );
    });
  });
});
