import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";
import { p256 } from "@noble/curves/p256";
import {
  SignatureRegistryV1,
  SovraDIDRegistryV1,
  SovraIssuerRegistryV1,
} from "../../typechain-types";
import { generateP256KeyPair, signP256, P256KeyPair } from "../wallet/helpers";

const DEFAULT_ADMIN_ROLE = ethers.ZeroHash;
const RECORDER_ROLE = ethers.keccak256(ethers.toUtf8Bytes("RECORDER_ROLE"));
const UPGRADER_ROLE = ethers.keccak256(ethers.toUtf8Bytes("UPGRADER_ROLE"));
const DID_MANAGER_ROLE = ethers.keccak256(ethers.toUtf8Bytes("DID_MANAGER_ROLE"));
const ISSUER_MANAGER_ROLE = ethers.keccak256(ethers.toUtf8Bytes("ISSUER_MANAGER_ROLE"));

const TYPE_ID = ethers.keccak256(ethers.toUtf8Bytes("DrivingLicenceCredential"));
const OTHER_TYPE_ID = ethers.keccak256(ethers.toUtf8Bytes("DiplomaCredential"));

/// Order of the P-256 curve, for flipping `s` into the high half.
const P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

// Key types and relationship bits, mirroring the DID registry's encoding.
const KEY_TYPE_P256 = 0;
const KEY_TYPE_SECP256K1 = 1;
const REL_AUTH = 1;
const REL_ASSERTION = 2;

function assertionMethod(key: P256KeyPair, overrides: Partial<{ keyType: number; relationships: number }> = {}) {
  return {
    id: ethers.keccak256(ethers.toUtf8Bytes("key-assert")),
    keyType: overrides.keyType ?? KEY_TYPE_P256,
    pubKeyX: key.publicKeyX,
    pubKeyY: key.publicKeyY,
    relationships: overrides.relationships ?? REL_ASSERTION,
  };
}

async function deployStack(admin: HardhatEthersSigner) {
  const didRegistry = (await upgrades.deployProxy(
    await ethers.getContractFactory("SovraDIDRegistryV1"),
    [admin.address],
    { kind: "uups" }
  )) as unknown as SovraDIDRegistryV1;

  const issuerRegistry = (await upgrades.deployProxy(
    await ethers.getContractFactory("SovraIssuerRegistryV1"),
    [admin.address],
    { kind: "uups" }
  )) as unknown as SovraIssuerRegistryV1;

  const registry = (await upgrades.deployProxy(
    await ethers.getContractFactory("SignatureRegistryV1"),
    [admin.address, await didRegistry.getAddress(), await issuerRegistry.getAddress()],
    { kind: "uups" }
  )) as unknown as SignatureRegistryV1;

  await registry.waitForDeployment();
  return { didRegistry, issuerRegistry, registry };
}

describe("SignatureRegistryV1", function () {
  let admin: HardhatEthersSigner;
  let outsider: HardhatEthersSigner;
  let signer: HardhatEthersSigner;
  let registry: SignatureRegistryV1;
  let didRegistry: SovraDIDRegistryV1;
  let issuerRegistry: SovraIssuerRegistryV1;
  let key: P256KeyPair;
  let digest: string;

  beforeEach(async function () {
    [admin, outsider, signer] = await ethers.getSigners();
    ({ didRegistry, issuerRegistry, registry } = await deployStack(admin));

    key = generateP256KeyPair();
    digest = ethers.keccak256(ethers.toUtf8Bytes("credential-payload"));

    await didRegistry.create(signer.address, [assertionMethod(key)], []);
    await issuerRegistry.registerIssuer(signer.address, [TYPE_ID]);
  });

  function sign(withKey: P256KeyPair = key, overDigest: string = digest) {
    return signP256(withKey.privateKey, overDigest);
  }

  // ─── Initialization ─────────────────────────────────

  describe("initialize", function () {
    it("grants all roles to admin and wires both registries", async function () {
      expect(await registry.hasRole(DEFAULT_ADMIN_ROLE, admin.address)).to.be.true;
      expect(await registry.hasRole(RECORDER_ROLE, admin.address)).to.be.true;
      expect(await registry.hasRole(UPGRADER_ROLE, admin.address)).to.be.true;
      expect(await registry.keyRegistry()).to.equal(await didRegistry.getAddress());
      expect(await registry.authorizationRegistry()).to.equal(await issuerRegistry.getAddress());
    });

    it("reverts on double initialization", async function () {
      await expect(
        registry.initialize(admin.address, await didRegistry.getAddress(), await issuerRegistry.getAddress())
      ).to.be.revertedWithCustomError(registry, "InvalidInitialization");
    });
  });

  // ─── Happy path ─────────────────────────────────────

  describe("record", function () {
    it("stores a valid signature and emits SignatureRecorded", async function () {
      const { r, s } = sign();
      await expect(registry.record(signer.address, TYPE_ID, digest, r, s))
        .to.emit(registry, "SignatureRecorded")
        .withArgs(signer.address, digest, (t: bigint) => t > 0n);

      expect(await registry.isRecorded(signer.address, digest)).to.be.true;

      const record = await registry.getRecord(signer.address, digest);
      expect(record.r).to.equal(r);
      expect(record.s).to.equal(s);
      expect(record.recordedAt).to.be.greaterThan(0n);
    });

    it("keys records by signer, so the same digest from two issuers is two records", async function () {
      const otherKey = generateP256KeyPair();
      await didRegistry.create(outsider.address, [assertionMethod(otherKey)], []);
      await issuerRegistry.registerIssuer(outsider.address, [TYPE_ID]);

      const a = sign();
      const b = signP256(otherKey.privateKey, digest);
      await registry.record(signer.address, TYPE_ID, digest, a.r, a.s);
      await registry.record(outsider.address, TYPE_ID, digest, b.r, b.s);

      expect(await registry.isRecorded(signer.address, digest)).to.be.true;
      expect(await registry.isRecorded(outsider.address, digest)).to.be.true;
    });

    it("returns an empty record for an unknown digest", async function () {
      const record = await registry.getRecord(signer.address, digest);
      expect(record.recordedAt).to.equal(0n);
      expect(await registry.isRecorded(signer.address, digest)).to.be.false;
    });

    // ─── Access control ───────────────────────────────

    it("reverts when the caller lacks RECORDER_ROLE", async function () {
      const { r, s } = sign();
      await expect(
        registry.connect(outsider).record(signer.address, TYPE_ID, digest, r, s)
      ).to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount");
    });

    // ─── Input and state guards ───────────────────────

    it("reverts on an empty digest", async function () {
      const { r, s } = sign();
      await expect(
        registry.record(signer.address, TYPE_ID, ethers.ZeroHash, r, s)
      ).to.be.revertedWithCustomError(registry, "EmptyDigest");
    });

    it("reverts when the same signer/digest pair is recorded twice", async function () {
      const { r, s } = sign();
      await registry.record(signer.address, TYPE_ID, digest, r, s);
      await expect(
        registry.record(signer.address, TYPE_ID, digest, r, s)
      ).to.be.revertedWithCustomError(registry, "AlreadyRecorded");
    });

    it("reverts when the signer is not trusted for the credential type", async function () {
      const { r, s } = sign();
      await expect(
        registry.record(signer.address, OTHER_TYPE_ID, digest, r, s)
      ).to.be.revertedWithCustomError(registry, "NotAuthorized");
    });

    it("reverts when the signer has no DID at all", async function () {
      await issuerRegistry.registerIssuer(outsider.address, [TYPE_ID]);
      const { r, s } = sign();
      await expect(
        registry.record(outsider.address, TYPE_ID, digest, r, s)
      ).to.be.revertedWithCustomError(registry, "NoRegisteredKey");
    });

    it("reverts when the DID has a P-256 key without the assertion bit", async function () {
      const authOnly = generateP256KeyPair();
      await didRegistry.create(
        outsider.address,
        [assertionMethod(authOnly, { relationships: REL_AUTH })],
        []
      );
      await issuerRegistry.registerIssuer(outsider.address, [TYPE_ID]);

      const { r, s } = signP256(authOnly.privateKey, digest);
      await expect(
        registry.record(outsider.address, TYPE_ID, digest, r, s)
      ).to.be.revertedWithCustomError(registry, "NoRegisteredKey");
    });

    it("reverts when the DID's assertion key is not P-256", async function () {
      const wrongCurve = generateP256KeyPair();
      await didRegistry.create(
        outsider.address,
        [assertionMethod(wrongCurve, { keyType: KEY_TYPE_SECP256K1 })],
        []
      );
      await issuerRegistry.registerIssuer(outsider.address, [TYPE_ID]);

      const { r, s } = signP256(wrongCurve.privateKey, digest);
      await expect(
        registry.record(outsider.address, TYPE_ID, digest, r, s)
      ).to.be.revertedWithCustomError(registry, "NoRegisteredKey");
    });

    // ─── Signature verification ───────────────────────

    it("reverts when the digest was not the one signed", async function () {
      const { r, s } = sign(key, ethers.keccak256(ethers.toUtf8Bytes("other-payload")));
      await expect(
        registry.record(signer.address, TYPE_ID, digest, r, s)
      ).to.be.revertedWithCustomError(registry, "InvalidSignature");
    });

    it("reverts when the signature came from a different key", async function () {
      const { r, s } = sign(generateP256KeyPair());
      await expect(
        registry.record(signer.address, TYPE_ID, digest, r, s)
      ).to.be.revertedWithCustomError(registry, "InvalidSignature");
    });

    it("rejects the high-s twin of an otherwise valid signature", async function () {
      const { r, s } = sign();
      const flipped = ethers.toBeHex(P256_N - BigInt(s), 32);
      // (r, n - s) verifies under textbook ECDSA; only the canonical half is accepted.
      await expect(
        registry.record(signer.address, TYPE_ID, digest, r, flipped)
      ).to.be.revertedWithCustomError(registry, "InvalidSignature");
    });

    it("rejects a zero r and a zero s", async function () {
      const { r, s } = sign();
      await expect(
        registry.record(signer.address, TYPE_ID, digest, ethers.ZeroHash, s)
      ).to.be.revertedWithCustomError(registry, "InvalidSignature");
      await expect(
        registry.record(signer.address, TYPE_ID, digest, r, ethers.ZeroHash)
      ).to.be.revertedWithCustomError(registry, "InvalidSignature");
    });

    it("rejects an r at or above the curve order", async function () {
      const { s } = sign();
      await expect(
        registry.record(signer.address, TYPE_ID, digest, ethers.toBeHex(P256_N, 32), s)
      ).to.be.revertedWithCustomError(registry, "InvalidSignature");
    });

    it("rejects a signature against an off-curve public key", async function () {
      const offCurve = generateP256KeyPair();
      // Flip one bit of Y so (x, y) no longer satisfies the Weierstrass equation.
      const brokenY = ethers.toBeHex(BigInt(offCurve.publicKeyY) ^ 1n, 32);
      await didRegistry.create(
        outsider.address,
        [{ ...assertionMethod(offCurve), pubKeyY: brokenY }],
        []
      );
      await issuerRegistry.registerIssuer(outsider.address, [TYPE_ID]);

      const { r, s } = signP256(offCurve.privateKey, digest);
      await expect(
        registry.record(outsider.address, TYPE_ID, digest, r, s)
      ).to.be.revertedWithCustomError(registry, "InvalidSignature");
    });

    it("leaves no record behind when verification fails", async function () {
      const { r, s } = sign(generateP256KeyPair());
      await expect(registry.record(signer.address, TYPE_ID, digest, r, s)).to.be.reverted;
      expect(await registry.isRecorded(signer.address, digest)).to.be.false;
    });
  });

  // ─── Roles ──────────────────────────────────────────

  describe("upgrade authorization", function () {
    it("reverts when the caller lacks UPGRADER_ROLE", async function () {
      const impl = await (await ethers.getContractFactory("SignatureRegistryV1")).deploy();
      await expect(
        registry.connect(outsider).upgradeToAndCall(await impl.getAddress(), "0x")
      ).to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount");
    });
  });
});
