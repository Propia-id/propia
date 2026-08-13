import { expect } from "chai";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import {
  assertDeployerHandoff,
  handoffWarnings,
  loadChainConfig,
  parseChainConfig,
  roleId,
} from "../scripts/chain-config";

const OWNER = "0x5555555555555555555555555555555555555555";
const COUNCIL = "0x4444444444444444444444444444444444444444";
const ADMIN = "0x1111111111111111111111111111111111111111";
const UPGRADER = "0x2222222222222222222222222222222222222222";
const BACKEND = "0x3333333333333333333333333333333333333333";
const ZERO = "0x0000000000000000000000000000000000000000";
const OUTSIDER = "0x6666666666666666666666666666666666666666";
/// Same address in both single-case forms — ethers accepts either and
/// normalises them to one checksummed value.
const LETTERS_LOWER = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd";
const LETTERS_UPPER = "0xABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD";

/// A minimal valid file with one network, "testnet".
function validRaw(): any {
  return {
    testnet: {
      beaconOwner: OWNER,
      securityCouncil: COUNCIL,
      renounceDeployer: true,
      roles: {
        SovraDIDRegistryV1: {
          DEFAULT_ADMIN_ROLE: [ADMIN],
          DID_MANAGER_ROLE: [BACKEND],
          UPGRADER_ROLE: [UPGRADER],
        },
        SovraIssuerRegistryV1: {
          DEFAULT_ADMIN_ROLE: [ADMIN],
          ISSUER_MANAGER_ROLE: [BACKEND],
          UPGRADER_ROLE: [UPGRADER],
        },
        SovraRevocationRegistryV1: {
          DEFAULT_ADMIN_ROLE: [ADMIN],
          STATUS_MANAGER_ROLE: [BACKEND],
          UPGRADER_ROLE: [UPGRADER],
        },
        SignatureRegistryV1: {
          DEFAULT_ADMIN_ROLE: [ADMIN],
          RECORDER_ROLE: [BACKEND],
          UPGRADER_ROLE: [UPGRADER],
        },
      },
    },
  };
}

function parse(mutate: (raw: any) => void = () => {}) {
  const raw = validRaw();
  mutate(raw);
  return parseChainConfig(raw, "testnet");
}

describe("chain-config", function () {
  // ─── Role identifiers ───────────────────────────────

  describe("roleId", function () {
    it("matches the AccessControl identifiers used by the registries", function () {
      expect(roleId("DEFAULT_ADMIN_ROLE")).to.equal(
        "0x0000000000000000000000000000000000000000000000000000000000000000"
      );
      expect(roleId("DID_MANAGER_ROLE")).to.equal(
        "0x04637b0fe92d45c99f497568ce3d712f8741ebf550f05a41f673f5fc6fed31e8"
      );
      expect(roleId("ISSUER_MANAGER_ROLE")).to.equal(
        "0x738c5e3640b4c77978b95a8ce8efad4c7e3f0efb91840e850b39c1a948db0915"
      );
      expect(roleId("STATUS_MANAGER_ROLE")).to.equal(
        "0xaecd6124097a9eb0b4f41f484962446a098f1e215d44c9b40ad6eec824056713"
      );
      expect(roleId("UPGRADER_ROLE")).to.equal(
        "0x189ab7a9244df0848122154315af71fe140f3db0fe014031783b0946b8c9d2e3"
      );
    });
  });

  // ─── Accepted input ─────────────────────────────────

  describe("parseChainConfig", function () {
    it("returns the requested network entry", function () {
      const config = parse();
      expect(config.network).to.equal("testnet");
      expect(config.beaconOwner).to.equal(OWNER);
      expect(config.securityCouncil).to.equal(COUNCIL);
      expect(config.renounceDeployer).to.be.true;
      expect(config.roles.SovraDIDRegistryV1.DID_MANAGER_ROLE).to.deep.equal([BACKEND]);
      expect(config.roles.SovraRevocationRegistryV1.STATUS_MANAGER_ROLE).to.deep.equal([BACKEND]);
    });

    it("normalises holder addresses to their checksummed form", function () {
      const holders = (address: string) =>
        parse((raw) => (raw.testnet.roles.SovraDIDRegistryV1.DID_MANAGER_ROLE = [address]))
          .roles.SovraDIDRegistryV1.DID_MANAGER_ROLE[0];

      const fromLower = holders(LETTERS_LOWER);
      expect(holders(LETTERS_UPPER)).to.equal(fromLower);
      expect(fromLower).to.not.equal(LETTERS_LOWER);
      expect(fromLower.toLowerCase()).to.equal(LETTERS_LOWER);
    });

    it("accepts several holders for one role", function () {
      const config = parse((raw) => {
        raw.testnet.roles.SovraDIDRegistryV1.DID_MANAGER_ROLE = [BACKEND, UPGRADER];
      });
      expect(config.roles.SovraDIDRegistryV1.DID_MANAGER_ROLE).to.deep.equal([BACKEND, UPGRADER]);
    });

    it("ignores keys starting with an underscore", function () {
      const config = parse((raw) => {
        raw._comment = "file note";
        raw.testnet._comment = "entry note";
      });
      expect(config.network).to.equal("testnet");
    });

    // ─── Rejected input ───────────────────────────────

    it("rejects a non-object file", function () {
      expect(() => parseChainConfig([], "testnet")).to.throw("must be an object");
    });

    it("rejects an unknown network and lists the known ones", function () {
      const raw = validRaw();
      raw.mainnet = raw.testnet;
      expect(() => parseChainConfig(raw, "l2")).to.throw(
        'no entry for network "l2" (available: testnet, mainnet)'
      );
    });

    it("rejects a missing setting", function () {
      expect(() => parse((raw) => delete raw.testnet.beaconOwner)).to.throw(
        "testnet.beaconOwner is missing"
      );
    });

    it("rejects an unknown setting", function () {
      expect(() => parse((raw) => (raw.testnet.admin = ADMIN))).to.throw(
        "testnet.admin is not a known setting"
      );
    });

    it("rejects a non-boolean renounceDeployer", function () {
      expect(() => parse((raw) => (raw.testnet.renounceDeployer = "true"))).to.throw(
        "testnet.renounceDeployer must be true or false"
      );
    });

    it("rejects a missing registry", function () {
      expect(() => parse((raw) => delete raw.testnet.roles.SovraIssuerRegistryV1)).to.throw(
        "testnet.roles is missing SovraIssuerRegistryV1"
      );
    });

    it("rejects an unknown registry", function () {
      expect(() => parse((raw) => (raw.testnet.roles.SovraWalletV1 = {}))).to.throw(
        "testnet.roles.SovraWalletV1 is not a role-managed contract"
      );
    });

    it("rejects a role the contract does not declare", function () {
      expect(
        () => parse((raw) => (raw.testnet.roles.SovraDIDRegistryV1.ISSUER_MANAGER_ROLE = [ADMIN]))
      ).to.throw("is not a role on SovraDIDRegistryV1");
    });

    it("rejects a missing role", function () {
      expect(() => parse((raw) => delete raw.testnet.roles.SovraDIDRegistryV1.UPGRADER_ROLE)).to.throw(
        "testnet.roles.SovraDIDRegistryV1 is missing UPGRADER_ROLE"
      );
    });

    it("rejects an empty holder list", function () {
      expect(() => parse((raw) => (raw.testnet.roles.SovraDIDRegistryV1.UPGRADER_ROLE = []))).to.throw(
        "testnet.roles.SovraDIDRegistryV1.UPGRADER_ROLE is empty"
      );
    });

    it("rejects a non-array holder list", function () {
      expect(() => parse((raw) => (raw.testnet.roles.SovraDIDRegistryV1.UPGRADER_ROLE = ADMIN))).to.throw(
        "must be an array of addresses"
      );
    });

    it("rejects the zero address", function () {
      expect(() => parse((raw) => (raw.testnet.roles.SovraDIDRegistryV1.UPGRADER_ROLE = [ZERO]))).to.throw(
        "UPGRADER_ROLE[0] is the zero address"
      );
    });

    it("rejects the zero address as security council", function () {
      expect(() => parse((raw) => (raw.testnet.securityCouncil = ZERO))).to.throw(
        "testnet.securityCouncil is the zero address"
      );
    });

    it("rejects a malformed address", function () {
      expect(() => parse((raw) => (raw.testnet.beaconOwner = "0xnothex"))).to.throw(
        "testnet.beaconOwner is not a valid address"
      );
    });

    it("rejects a non-string address", function () {
      expect(() => parse((raw) => (raw.testnet.beaconOwner = 42))).to.throw(
        "testnet.beaconOwner must be a string"
      );
    });

    it("rejects the same holder twice, whatever the casing", function () {
      expect(() =>
        parse(
          (raw) =>
            (raw.testnet.roles.SovraDIDRegistryV1.DID_MANAGER_ROLE = [
              LETTERS_LOWER,
              LETTERS_UPPER,
            ])
        )
      ).to.throw("more than once");
    });
  });

  // ─── Handoff safety ─────────────────────────────────

  describe("assertDeployerHandoff", function () {
    it("passes when the deployer holds nothing in the config", function () {
      expect(() => assertDeployerHandoff(parse(), OWNER)).to.not.throw();
    });

    it("rejects a renouncing deploy that also lists the deployer", function () {
      const config = parse();
      expect(() => assertDeployerHandoff(config, BACKEND)).to.throw(
        "lists the deployer"
      );
    });

    it("compares addresses case-insensitively", function () {
      const config = parse(
        (raw) => (raw.testnet.roles.SovraDIDRegistryV1.DID_MANAGER_ROLE = [LETTERS_LOWER])
      );
      expect(() => assertDeployerHandoff(config, LETTERS_UPPER)).to.throw("lists the deployer");
    });

    it("allows the deployer to be listed when it keeps its roles", function () {
      const config = parse((raw) => (raw.testnet.renounceDeployer = false));
      expect(() => assertDeployerHandoff(config, BACKEND)).to.not.throw();
    });
  });

  describe("handoffWarnings", function () {
    it("is silent for a clean separation of duties", function () {
      expect(handoffWarnings(parse(), OUTSIDER)).to.deep.equal([]);
    });

    it("warns when the deploy key keeps its roles", function () {
      const config = parse((raw) => (raw.testnet.renounceDeployer = false));
      const warnings = handoffWarnings(config, OUTSIDER);
      expect(warnings).to.have.lengthOf(1);
      expect(warnings[0]).to.contain("renounceDeployer is false");
    });

    it("warns when the deploy key is the security council", function () {
      const warnings = handoffWarnings(parse(), COUNCIL);
      expect(warnings.some((w) => w.includes("bypasses the"))).to.be.true;
    });

    it("warns when the council and the beacon owner are the same address", function () {
      const config = parse((raw) => (raw.testnet.securityCouncil = OWNER));
      const warnings = handoffWarnings(config, OUTSIDER);
      expect(warnings.some((w) => w.includes("equals beaconOwner"))).to.be.true;
    });
  });

  // ─── File loading ───────────────────────────────────

  describe("loadChainConfig", function () {
    let tmpDir: string;

    before(function () {
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sovra-chain-config-"));
    });

    after(function () {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    it("loads the committed chain/config.json for the local network", function () {
      const config = loadChainConfig("anvil");
      expect(config.network).to.equal("anvil");
      expect(config.renounceDeployer).to.be.false;
      expect(config.roles.SovraIssuerRegistryV1.ISSUER_MANAGER_ROLE).to.have.length.greaterThan(0);
    });

    it("reports a missing file", function () {
      const missing = path.join(tmpDir, "absent.json");
      expect(() => loadChainConfig("testnet", missing)).to.throw(`not found at ${missing}`);
    });

    it("reports invalid JSON", function () {
      const broken = path.join(tmpDir, "broken.json");
      fs.writeFileSync(broken, "{ not json");
      expect(() => loadChainConfig("testnet", broken)).to.throw("invalid JSON");
    });

    it("loads a valid file from disk", function () {
      const file = path.join(tmpDir, "config.json");
      fs.writeFileSync(file, JSON.stringify(validRaw()));
      expect(loadChainConfig("testnet", file).beaconOwner).to.equal(OWNER);
    });
  });
});
