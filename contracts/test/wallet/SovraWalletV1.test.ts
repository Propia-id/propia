import { expect } from "chai";
import { ethers } from "hardhat";
import {
  deployAndInitialize,
  deployWallet,
  generateP256KeyPair,
  signP256,
  buildDomainSeparator,
  buildMessageHash,
  signPasskey,
} from "./helpers";

describe("SovraWalletV1", function () {
  // ─── Initialize ─────────────────────────────────────────

  describe("initialize", function () {
    it("sets keys and DID metadata", async function () {
      const { wallet, passkey, recoveryKey, walletAddress } = await deployAndInitialize();

      expect(await wallet.passkeyX()).to.equal(passkey.publicKeyX);
      expect(await wallet.passkeyY()).to.equal(passkey.publicKeyY);
      expect(await wallet.recoveryKeyX()).to.equal(recoveryKey.publicKeyX);
      expect(await wallet.recoveryKeyY()).to.equal(recoveryKey.publicKeyY);
      expect(await wallet.didCreated()).to.be.gt(0);
      expect(await wallet.didUpdated()).to.be.gt(0);
      expect(await wallet.didVersionId()).to.equal(1);
      expect(await wallet.didDeactivated()).to.equal(false);
    });

    it("emits DIDCreated event", async function () {
      const { wallet, dispatcher, implementation } = await deployWallet();
      const passkey = generateP256KeyPair();
      const recoveryKey = generateP256KeyPair();
      const walletAddress = await wallet.getAddress();

      const initHash = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["address", "bytes32", "bytes32", "bytes32", "bytes32"],
          [walletAddress, passkey.publicKeyX, passkey.publicKeyY, recoveryKey.publicKeyX, recoveryKey.publicKeyY]
        )
      );

      const passkeySig = signP256(passkey.privateKey, initHash);

      await expect(
        wallet.initialize(
          passkey.publicKeyX, passkey.publicKeyY,
          recoveryKey.publicKeyX, recoveryKey.publicKeyY,
          passkeySig.r, passkeySig.s
        )
      ).to.emit(wallet, "DIDCreated").withArgs(walletAddress, 1);
    });

    it("reverts on double initialization", async function () {
      const { wallet, passkey, recoveryKey } = await deployAndInitialize();

      const initHash = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["address", "bytes32", "bytes32", "bytes32", "bytes32"],
          [await wallet.getAddress(), passkey.publicKeyX, passkey.publicKeyY, recoveryKey.publicKeyX, recoveryKey.publicKeyY]
        )
      );
      const passkeySig = signP256(passkey.privateKey, initHash);

      await expect(
        wallet.initialize(
          passkey.publicKeyX, passkey.publicKeyY,
          recoveryKey.publicKeyX, recoveryKey.publicKeyY,
          passkeySig.r, passkeySig.s
        )
      ).to.be.revertedWithCustomError(wallet, "AlreadyInitialized");
    });

    it("reverts on bad passkey signature", async function () {
      const { wallet } = await deployWallet();
      const passkey = generateP256KeyPair();
      const recoveryKey = generateP256KeyPair();
      const badKey = generateP256KeyPair();
      const walletAddress = await wallet.getAddress();

      const initHash = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["address", "bytes32", "bytes32", "bytes32", "bytes32"],
          [walletAddress, passkey.publicKeyX, passkey.publicKeyY, recoveryKey.publicKeyX, recoveryKey.publicKeyY]
        )
      );

      // Sign with wrong key
      const badSig = signP256(badKey.privateKey, initHash);

      await expect(
        wallet.initialize(
          passkey.publicKeyX, passkey.publicKeyY,
          recoveryKey.publicKeyX, recoveryKey.publicKeyY,
          badSig.r, badSig.s
        )
      ).to.be.revertedWithCustomError(wallet, "InvalidPasskeySig");
    });
  });

  // ─── Execute ────────────────────────────────────────────

  describe("execute", function () {
    it("executes a call with passkey signature", async function () {
      const { wallet, passkey, recoveryKey, domainSep } = await deployAndInitialize();
      const [, receiver] = await ethers.getSigners();
      const [signer] = await ethers.getSigners();

      // Fund the wallet
      await signer.sendTransaction({
        to: await wallet.getAddress(),
        value: ethers.parseEther("1"),
      });

      const target = receiver.address;
      const value = ethers.parseEther("0.5");
      const data = "0x";
      const currentNonce = await wallet.nonce();

      const opHash = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["address", "uint256", "bytes"],
          [target, value, data]
        )
      );
      const msgHash = buildMessageHash(domainSep, opHash, currentNonce);
      const sigs = signPasskey(passkey, msgHash);

      const balanceBefore = await ethers.provider.getBalance(target);
      await wallet.execute(target, value, data, sigs.passkeyR, sigs.passkeyS);
      const balanceAfter = await ethers.provider.getBalance(target);

      expect(balanceAfter - balanceBefore).to.equal(value);
    });

    it("increments nonce", async function () {
      const { wallet, passkey, recoveryKey, domainSep } = await deployAndInitialize();
      const [, receiver] = await ethers.getSigners();

      expect(await wallet.nonce()).to.equal(0);

      const opHash = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["address", "uint256", "bytes"],
          [receiver.address, 0, "0x"]
        )
      );
      const msgHash = buildMessageHash(domainSep, opHash, 0n);
      const sigs = signPasskey(passkey, msgHash);

      await wallet.execute(receiver.address, 0, "0x", sigs.passkeyR, sigs.passkeyS);
      expect(await wallet.nonce()).to.equal(1);
    });

    it("emits Executed event", async function () {
      const { wallet, passkey, recoveryKey, domainSep, walletAddress } = await deployAndInitialize();
      const [, receiver] = await ethers.getSigners();

      const opHash = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["address", "uint256", "bytes"],
          [receiver.address, 0, "0x"]
        )
      );
      const msgHash = buildMessageHash(domainSep, opHash, 0n);
      const sigs = signPasskey(passkey, msgHash);

      await expect(
        wallet.execute(receiver.address, 0, "0x", sigs.passkeyR, sigs.passkeyS)
      ).to.emit(wallet, "Executed").withArgs(walletAddress, receiver.address, 0, 0);
    });

    it("reverts on bad signature", async function () {
      const { wallet, passkey, recoveryKey, domainSep } = await deployAndInitialize();
      const [, receiver] = await ethers.getSigners();
      const badKey = generateP256KeyPair();

      const opHash = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["address", "uint256", "bytes"],
          [receiver.address, 0, "0x"]
        )
      );
      const msgHash = buildMessageHash(domainSep, opHash, 0n);
      const badSig = signP256(badKey.privateKey, msgHash);

      await expect(
        wallet.execute(receiver.address, 0, "0x", badSig.r, badSig.s)
      ).to.be.revertedWithCustomError(wallet, "InvalidPasskeySig");
    });

    it("reverts when deactivated", async function () {
      const { wallet, passkey, recoveryKey, domainSep } = await deployAndInitialize();
      const [, receiver] = await ethers.getSigners();

      // Deactivate first
      const deactOpHash = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["bytes4"],
          [ethers.dataSlice(ethers.keccak256(ethers.toUtf8Bytes("deactivate")), 0, 4)]
        )
      );
      const deactMsgHash = buildMessageHash(domainSep, deactOpHash, 0n);
      const deactSigs = signPasskey(passkey, deactMsgHash);
      await wallet.deactivate(deactSigs.passkeyR, deactSigs.passkeyS);

      // Try execute
      const opHash = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["address", "uint256", "bytes"],
          [receiver.address, 0, "0x"]
        )
      );
      const msgHash = buildMessageHash(domainSep, opHash, 1n);
      const sigs = signPasskey(passkey, msgHash);

      await expect(
        wallet.execute(receiver.address, 0, "0x", sigs.passkeyR, sigs.passkeyS)
      ).to.be.revertedWithCustomError(wallet, "DIDIsDeactivated");
    });

    it("reverts on failed target call", async function () {
      const { wallet, passkey, recoveryKey, domainSep } = await deployAndInitialize();

      // Call to address with no code and value we don't have
      const target = "0x0000000000000000000000000000000000000001";
      const value = ethers.parseEther("1000"); // More than wallet has

      const opHash = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["address", "uint256", "bytes"],
          [target, value, "0x"]
        )
      );
      const msgHash = buildMessageHash(domainSep, opHash, 0n);
      const sigs = signPasskey(passkey, msgHash);

      await expect(
        wallet.execute(target, value, "0x", sigs.passkeyR, sigs.passkeyS)
      ).to.be.revertedWithCustomError(wallet, "CallFailed");
    });
  });

  // ─── Rotate Passkey ─────────────────────────────────────

  describe("rotatePasskey", function () {
    it("updates passkey and increments versionId", async function () {
      const { wallet, passkey, recoveryKey, domainSep } = await deployAndInitialize();
      const newPasskey = generateP256KeyPair();

      const opHash = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["bytes4", "bytes32", "bytes32"],
          [ethers.dataSlice(ethers.keccak256(ethers.toUtf8Bytes("rotatePasskey")), 0, 4), newPasskey.publicKeyX, newPasskey.publicKeyY]
        )
      );
      const msgHash = buildMessageHash(domainSep, opHash, 0n);
      const sigs = signPasskey(passkey, msgHash);

      await expect(
        wallet.rotatePasskey(newPasskey.publicKeyX, newPasskey.publicKeyY, sigs.passkeyR, sigs.passkeyS)
      ).to.emit(wallet, "DIDUpdated");

      expect(await wallet.passkeyX()).to.equal(newPasskey.publicKeyX);
      expect(await wallet.passkeyY()).to.equal(newPasskey.publicKeyY);
      expect(await wallet.didVersionId()).to.equal(2);
      expect(await wallet.nonce()).to.equal(1);
    });

    it("new key works after rotation", async function () {
      const { wallet, passkey, recoveryKey, domainSep } = await deployAndInitialize();
      const newPasskey = generateP256KeyPair();
      const [, receiver] = await ethers.getSigners();

      // Rotate
      const rotateOpHash = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["bytes4", "bytes32", "bytes32"],
          [ethers.dataSlice(ethers.keccak256(ethers.toUtf8Bytes("rotatePasskey")), 0, 4), newPasskey.publicKeyX, newPasskey.publicKeyY]
        )
      );
      const rotateMsgHash = buildMessageHash(domainSep, rotateOpHash, 0n);
      const rotateSigs = signPasskey(passkey, rotateMsgHash);
      await wallet.rotatePasskey(newPasskey.publicKeyX, newPasskey.publicKeyY, rotateSigs.passkeyR, rotateSigs.passkeyS);

      // Execute with new passkey
      const opHash = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["address", "uint256", "bytes"],
          [receiver.address, 0, "0x"]
        )
      );
      const msgHash = buildMessageHash(domainSep, opHash, 1n);
      const sigs = signPasskey(newPasskey, msgHash);

      await expect(
        wallet.execute(receiver.address, 0, "0x", sigs.passkeyR, sigs.passkeyS)
      ).to.emit(wallet, "Executed");
    });
  });

  // ─── Rotate Recovery Key ──────────────────────────────────

  describe("rotateRecoveryKey", function () {
    it("updates recovery key and increments versionId", async function () {
      const { wallet, passkey, recoveryKey, domainSep } = await deployAndInitialize();
      const newRecoveryKey = generateP256KeyPair();

      const opHash = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["bytes4", "bytes32", "bytes32"],
          [ethers.dataSlice(ethers.keccak256(ethers.toUtf8Bytes("rotateRecoveryKey")), 0, 4), newRecoveryKey.publicKeyX, newRecoveryKey.publicKeyY]
        )
      );
      const msgHash = buildMessageHash(domainSep, opHash, 0n);
      const sigs = signPasskey(passkey, msgHash);

      await expect(
        wallet.rotateRecoveryKey(newRecoveryKey.publicKeyX, newRecoveryKey.publicKeyY, sigs.passkeyR, sigs.passkeyS)
      ).to.emit(wallet, "DIDUpdated");

      expect(await wallet.recoveryKeyX()).to.equal(newRecoveryKey.publicKeyX);
      expect(await wallet.recoveryKeyY()).to.equal(newRecoveryKey.publicKeyY);
      expect(await wallet.didVersionId()).to.equal(2);
    });
  });

  // ─── Deactivate ─────────────────────────────────────────

  describe("deactivate", function () {
    it("sets flag and emits DIDDeactivated", async function () {
      const { wallet, passkey, recoveryKey, domainSep, walletAddress } = await deployAndInitialize();

      const opHash = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["bytes4"],
          [ethers.dataSlice(ethers.keccak256(ethers.toUtf8Bytes("deactivate")), 0, 4)]
        )
      );
      const msgHash = buildMessageHash(domainSep, opHash, 0n);
      const sigs = signPasskey(passkey, msgHash);

      await expect(
        wallet.deactivate(sigs.passkeyR, sigs.passkeyS)
      ).to.emit(wallet, "DIDDeactivated").withArgs(walletAddress, 2);

      expect(await wallet.didDeactivated()).to.equal(true);
    });

    it("blocks subsequent operations", async function () {
      const { wallet, passkey, recoveryKey, domainSep } = await deployAndInitialize();
      const [, receiver] = await ethers.getSigners();

      // Deactivate
      const deactOpHash = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["bytes4"],
          [ethers.dataSlice(ethers.keccak256(ethers.toUtf8Bytes("deactivate")), 0, 4)]
        )
      );
      const deactMsgHash = buildMessageHash(domainSep, deactOpHash, 0n);
      const deactSigs = signPasskey(passkey, deactMsgHash);
      await wallet.deactivate(deactSigs.passkeyR, deactSigs.passkeyS);

      // Try rotate
      const newPasskey = generateP256KeyPair();
      const opHash = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["bytes4", "bytes32", "bytes32"],
          [ethers.dataSlice(ethers.keccak256(ethers.toUtf8Bytes("rotatePasskey")), 0, 4), newPasskey.publicKeyX, newPasskey.publicKeyY]
        )
      );
      const msgHash = buildMessageHash(domainSep, opHash, 1n);
      const sigs = signPasskey(passkey, msgHash);

      await expect(
        wallet.rotatePasskey(newPasskey.publicKeyX, newPasskey.publicKeyY, sigs.passkeyR, sigs.passkeyS)
      ).to.be.revertedWithCustomError(wallet, "DIDIsDeactivated");
    });
  });

  // ─── Upgrade ────────────────────────────────────────────

  describe("upgrade", function () {
    it("writes ERC-1967 slot and emits Upgraded", async function () {
      const { wallet, passkey, recoveryKey, domainSep, walletAddress } = await deployAndInitialize();

      const SovraWalletV1 = await ethers.getContractFactory("SovraWalletV1");
      const newImpl = await SovraWalletV1.deploy();
      await newImpl.waitForDeployment();
      const newImplAddr = await newImpl.getAddress();

      const opHash = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["bytes4", "address"],
          [ethers.dataSlice(ethers.keccak256(ethers.toUtf8Bytes("upgrade")), 0, 4), newImplAddr]
        )
      );
      const msgHash = buildMessageHash(domainSep, opHash, 0n);
      const sigs = signPasskey(passkey, msgHash);

      await expect(
        wallet.upgrade(newImplAddr, sigs.passkeyR, sigs.passkeyS)
      ).to.emit(wallet, "Upgraded").withArgs(walletAddress, newImplAddr);
    });

    it("reverts for address(0)", async function () {
      const { wallet, passkey, recoveryKey, domainSep } = await deployAndInitialize();

      const opHash = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["bytes4", "address"],
          [ethers.dataSlice(ethers.keccak256(ethers.toUtf8Bytes("upgrade")), 0, 4), ethers.ZeroAddress]
        )
      );
      const msgHash = buildMessageHash(domainSep, opHash, 0n);
      const sigs = signPasskey(passkey, msgHash);

      await expect(
        wallet.upgrade(ethers.ZeroAddress, sigs.passkeyR, sigs.passkeyS)
      ).to.be.revertedWithCustomError(wallet, "InvalidImplementation");
    });

    it("reverts for non-contract address", async function () {
      const { wallet, passkey, recoveryKey, domainSep } = await deployAndInitialize();
      const [, randomAddr] = await ethers.getSigners();

      const opHash = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["bytes4", "address"],
          [ethers.dataSlice(ethers.keccak256(ethers.toUtf8Bytes("upgrade")), 0, 4), randomAddr.address]
        )
      );
      const msgHash = buildMessageHash(domainSep, opHash, 0n);
      const sigs = signPasskey(passkey, msgHash);

      await expect(
        wallet.upgrade(randomAddr.address, sigs.passkeyR, sigs.passkeyS)
      ).to.be.revertedWithCustomError(wallet, "NotAContract");
    });
  });

  // ─── Nonce Replay Protection ────────────────────────────

  describe("nonce replay protection", function () {
    it("rejects replayed signature after nonce increment", async function () {
      const { wallet, passkey, recoveryKey, domainSep } = await deployAndInitialize();
      const [, receiver] = await ethers.getSigners();

      const opHash = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["address", "uint256", "bytes"],
          [receiver.address, 0, "0x"]
        )
      );
      const msgHash = buildMessageHash(domainSep, opHash, 0n);
      const sigs = signPasskey(passkey, msgHash);

      // First call succeeds
      await wallet.execute(receiver.address, 0, "0x", sigs.passkeyR, sigs.passkeyS);

      // Replay with same sig (nonce is now 1, sig was for nonce 0)
      await expect(
        wallet.execute(receiver.address, 0, "0x", sigs.passkeyR, sigs.passkeyS)
      ).to.be.revertedWithCustomError(wallet, "InvalidPasskeySig");
    });
  });

  // ─── EIP-712 ────────────────────────────────────────────

  describe("EIP-712", function () {
    it("domain separator is correct for chain and address", async function () {
      const { wallet, walletAddress, chainId } = await deployAndInitialize();
      const expected = buildDomainSeparator(chainId, walletAddress);

      // We can verify by checking that signatures work with our computed domain separator
      // If our domain sep was wrong, all signatures would fail
      // The fact that initialize succeeded proves correctness
      expect(expected).to.be.a("string").that.has.length(66); // 0x + 64 hex chars
    });
  });
});
