import { expect } from "chai";
import { ethers, network } from "hardhat";
import {
  deployAndInitialize,
  generateP256KeyPair,
  signP256,
  buildMessageHash,
  signPasskey,
} from "./helpers";

describe("Recovery", function () {
  // ─── Initiate Recovery ──────────────────────────────────

  describe("initiateRecovery", function () {
    it("server initiates passkey replacement", async function () {
      const { wallet, recoveryKey, domainSep, walletAddress } = await deployAndInitialize();
      const newPasskey = generateP256KeyPair();

      const opHash = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["bytes4", "bytes32", "bytes32", "uint8"],
          [ethers.dataSlice(ethers.keccak256(ethers.toUtf8Bytes("initiateRecovery")), 0, 4), newPasskey.publicKeyX, newPasskey.publicKeyY, 0]
        )
      );
      const msgHash = buildMessageHash(domainSep, opHash, 0n);
      const sig = signP256(recoveryKey.privateKey, msgHash);

      await expect(
        wallet.initiateRecovery(newPasskey.publicKeyX, newPasskey.publicKeyY, 0, sig.r, sig.s)
      ).to.emit(wallet, "RecoveryInitiated").withArgs(walletAddress, 0, newPasskey.publicKeyX, newPasskey.publicKeyY);

      const recovery = await wallet.pendingRecovery();
      expect(recovery[0]).to.equal(newPasskey.publicKeyX); // newKeyX
      expect(recovery[1]).to.equal(newPasskey.publicKeyY); // newKeyY
      expect(recovery[2]).to.equal(0); // keyToReplace
      expect(recovery[4]).to.equal(true); // active
    });

    it("passkey initiates server key replacement", async function () {
      const { wallet, passkey, domainSep } = await deployAndInitialize();
      const newRecoveryKey = generateP256KeyPair();

      const opHash = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["bytes4", "bytes32", "bytes32", "uint8"],
          [ethers.dataSlice(ethers.keccak256(ethers.toUtf8Bytes("initiateRecovery")), 0, 4), newRecoveryKey.publicKeyX, newRecoveryKey.publicKeyY, 1]
        )
      );
      const msgHash = buildMessageHash(domainSep, opHash, 0n);
      const sig = signP256(passkey.privateKey, msgHash);

      await expect(
        wallet.initiateRecovery(newRecoveryKey.publicKeyX, newRecoveryKey.publicKeyY, 1, sig.r, sig.s)
      ).to.emit(wallet, "RecoveryInitiated");
    });

    it("reverts if recovery already pending", async function () {
      const { wallet, recoveryKey, domainSep } = await deployAndInitialize();
      const newPasskey = generateP256KeyPair();

      // First initiation
      const opHash = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["bytes4", "bytes32", "bytes32", "uint8"],
          [ethers.dataSlice(ethers.keccak256(ethers.toUtf8Bytes("initiateRecovery")), 0, 4), newPasskey.publicKeyX, newPasskey.publicKeyY, 0]
        )
      );
      const msgHash = buildMessageHash(domainSep, opHash, 0n);
      const sig = signP256(recoveryKey.privateKey, msgHash);
      await wallet.initiateRecovery(newPasskey.publicKeyX, newPasskey.publicKeyY, 0, sig.r, sig.s);

      // Second initiation should fail
      const newPasskey2 = generateP256KeyPair();
      const opHash2 = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["bytes4", "bytes32", "bytes32", "uint8"],
          [ethers.dataSlice(ethers.keccak256(ethers.toUtf8Bytes("initiateRecovery")), 0, 4), newPasskey2.publicKeyX, newPasskey2.publicKeyY, 0]
        )
      );
      const msgHash2 = buildMessageHash(domainSep, opHash2, 1n);
      const sig2 = signP256(recoveryKey.privateKey, msgHash2);

      await expect(
        wallet.initiateRecovery(newPasskey2.publicKeyX, newPasskey2.publicKeyY, 0, sig2.r, sig2.s)
      ).to.be.revertedWithCustomError(wallet, "RecoveryAlreadyPending");
    });

    it("reverts if wrong key signs", async function () {
      const { wallet, passkey, domainSep } = await deployAndInitialize();
      const newPasskey = generateP256KeyPair();

      // Passkey tries to replace itself (should be recovery key signing)
      const opHash = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["bytes4", "bytes32", "bytes32", "uint8"],
          [ethers.dataSlice(ethers.keccak256(ethers.toUtf8Bytes("initiateRecovery")), 0, 4), newPasskey.publicKeyX, newPasskey.publicKeyY, 0]
        )
      );
      const msgHash = buildMessageHash(domainSep, opHash, 0n);
      const sig = signP256(passkey.privateKey, msgHash); // Wrong key!

      await expect(
        wallet.initiateRecovery(newPasskey.publicKeyX, newPasskey.publicKeyY, 0, sig.r, sig.s)
      ).to.be.revertedWithCustomError(wallet, "InvalidSig");
    });
  });

  // ─── Cancel Recovery ────────────────────────────────────

  describe("cancelRecovery", function () {
    it("either key cancels recovery", async function () {
      const { wallet, passkey, recoveryKey, domainSep, walletAddress } = await deployAndInitialize();
      const newPasskey = generateP256KeyPair();

      // Initiate
      const initOpHash = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["bytes4", "bytes32", "bytes32", "uint8"],
          [ethers.dataSlice(ethers.keccak256(ethers.toUtf8Bytes("initiateRecovery")), 0, 4), newPasskey.publicKeyX, newPasskey.publicKeyY, 0]
        )
      );
      const initMsgHash = buildMessageHash(domainSep, initOpHash, 0n);
      const initSig = signP256(recoveryKey.privateKey, initMsgHash);
      await wallet.initiateRecovery(newPasskey.publicKeyX, newPasskey.publicKeyY, 0, initSig.r, initSig.s);

      // Cancel with passkey (signerKey = 0)
      const cancelOpHash = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["bytes4"],
          [ethers.dataSlice(ethers.keccak256(ethers.toUtf8Bytes("cancelRecovery")), 0, 4)]
        )
      );
      const cancelMsgHash = buildMessageHash(domainSep, cancelOpHash, 1n);
      const cancelSig = signP256(passkey.privateKey, cancelMsgHash);

      await expect(
        wallet.cancelRecovery(cancelSig.r, cancelSig.s, 0)
      ).to.emit(wallet, "RecoveryCancelled").withArgs(walletAddress);

      const recovery = await wallet.pendingRecovery();
      expect(recovery[4]).to.equal(false); // active = false
    });

    it("reverts if no pending recovery", async function () {
      const { wallet, passkey, domainSep } = await deployAndInitialize();

      const cancelOpHash = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["bytes4"],
          [ethers.dataSlice(ethers.keccak256(ethers.toUtf8Bytes("cancelRecovery")), 0, 4)]
        )
      );
      const cancelMsgHash = buildMessageHash(domainSep, cancelOpHash, 0n);
      const cancelSig = signP256(passkey.privateKey, cancelMsgHash);

      await expect(
        wallet.cancelRecovery(cancelSig.r, cancelSig.s, 0)
      ).to.be.revertedWithCustomError(wallet, "NoRecoveryPending");
    });
  });

  // ─── Finalize Recovery ──────────────────────────────────

  describe("finalizeRecovery", function () {
    it("succeeds after 7 days and replaces key", async function () {
      const { wallet, recoveryKey, domainSep, walletAddress } = await deployAndInitialize();
      const newPasskey = generateP256KeyPair();

      // Initiate (recovery key replaces passkey)
      const initOpHash = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["bytes4", "bytes32", "bytes32", "uint8"],
          [ethers.dataSlice(ethers.keccak256(ethers.toUtf8Bytes("initiateRecovery")), 0, 4), newPasskey.publicKeyX, newPasskey.publicKeyY, 0]
        )
      );
      const initMsgHash = buildMessageHash(domainSep, initOpHash, 0n);
      const initSig = signP256(recoveryKey.privateKey, initMsgHash);
      await wallet.initiateRecovery(newPasskey.publicKeyX, newPasskey.publicKeyY, 0, initSig.r, initSig.s);

      // Advance time by 7 days
      await network.provider.send("evm_increaseTime", [7 * 24 * 60 * 60]);
      await network.provider.send("evm_mine");

      // Finalize (recovery key signs)
      const finalOpHash = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["bytes4"],
          [ethers.dataSlice(ethers.keccak256(ethers.toUtf8Bytes("finalizeRecovery")), 0, 4)]
        )
      );
      const finalMsgHash = buildMessageHash(domainSep, finalOpHash, 1n);
      const finalSig = signP256(recoveryKey.privateKey, finalMsgHash);

      await expect(
        wallet.finalizeRecovery(finalSig.r, finalSig.s)
      ).to.emit(wallet, "RecoveryFinalized").withArgs(walletAddress, 0);

      // Verify new key
      expect(await wallet.passkeyX()).to.equal(newPasskey.publicKeyX);
      expect(await wallet.passkeyY()).to.equal(newPasskey.publicKeyY);
      expect(await wallet.didVersionId()).to.equal(2);
    });

    it("reverts before 7-day delay", async function () {
      const { wallet, recoveryKey, domainSep } = await deployAndInitialize();
      const newPasskey = generateP256KeyPair();

      // Initiate
      const initOpHash = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["bytes4", "bytes32", "bytes32", "uint8"],
          [ethers.dataSlice(ethers.keccak256(ethers.toUtf8Bytes("initiateRecovery")), 0, 4), newPasskey.publicKeyX, newPasskey.publicKeyY, 0]
        )
      );
      const initMsgHash = buildMessageHash(domainSep, initOpHash, 0n);
      const initSig = signP256(recoveryKey.privateKey, initMsgHash);
      await wallet.initiateRecovery(newPasskey.publicKeyX, newPasskey.publicKeyY, 0, initSig.r, initSig.s);

      // Try to finalize immediately
      const finalOpHash = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["bytes4"],
          [ethers.dataSlice(ethers.keccak256(ethers.toUtf8Bytes("finalizeRecovery")), 0, 4)]
        )
      );
      const finalMsgHash = buildMessageHash(domainSep, finalOpHash, 1n);
      const finalSig = signP256(recoveryKey.privateKey, finalMsgHash);

      await expect(
        wallet.finalizeRecovery(finalSig.r, finalSig.s)
      ).to.be.revertedWithCustomError(wallet, "RecoveryDelayNotElapsed");
    });

    it("full flow: initiate -> wait -> finalize -> new key works", async function () {
      const { wallet, passkey, recoveryKey, domainSep } = await deployAndInitialize();
      const newPasskey = generateP256KeyPair();
      const [, receiver] = await ethers.getSigners();

      // Initiate (recovery key replaces passkey)
      const initOpHash = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["bytes4", "bytes32", "bytes32", "uint8"],
          [ethers.dataSlice(ethers.keccak256(ethers.toUtf8Bytes("initiateRecovery")), 0, 4), newPasskey.publicKeyX, newPasskey.publicKeyY, 0]
        )
      );
      const initMsgHash = buildMessageHash(domainSep, initOpHash, 0n);
      const initSig = signP256(recoveryKey.privateKey, initMsgHash);
      await wallet.initiateRecovery(newPasskey.publicKeyX, newPasskey.publicKeyY, 0, initSig.r, initSig.s);

      // Wait 7 days
      await network.provider.send("evm_increaseTime", [7 * 24 * 60 * 60]);
      await network.provider.send("evm_mine");

      // Finalize
      const finalOpHash = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["bytes4"],
          [ethers.dataSlice(ethers.keccak256(ethers.toUtf8Bytes("finalizeRecovery")), 0, 4)]
        )
      );
      const finalMsgHash = buildMessageHash(domainSep, finalOpHash, 1n);
      const finalSig = signP256(recoveryKey.privateKey, finalMsgHash);
      await wallet.finalizeRecovery(finalSig.r, finalSig.s);

      // Execute with new passkey
      const execOpHash = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["address", "uint256", "bytes"],
          [receiver.address, 0, "0x"]
        )
      );
      const execMsgHash = buildMessageHash(domainSep, execOpHash, 2n);
      const execSigs = signPasskey(newPasskey, execMsgHash);

      await expect(
        wallet.execute(receiver.address, 0, "0x", execSigs.passkeyR, execSigs.passkeyS)
      ).to.emit(wallet, "Executed");
    });

    it("cancel flow: initiate -> cancel -> old key still works", async function () {
      const { wallet, passkey, recoveryKey, domainSep } = await deployAndInitialize();
      const newPasskey = generateP256KeyPair();
      const [, receiver] = await ethers.getSigners();

      // Initiate
      const initOpHash = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["bytes4", "bytes32", "bytes32", "uint8"],
          [ethers.dataSlice(ethers.keccak256(ethers.toUtf8Bytes("initiateRecovery")), 0, 4), newPasskey.publicKeyX, newPasskey.publicKeyY, 0]
        )
      );
      const initMsgHash = buildMessageHash(domainSep, initOpHash, 0n);
      const initSig = signP256(recoveryKey.privateKey, initMsgHash);
      await wallet.initiateRecovery(newPasskey.publicKeyX, newPasskey.publicKeyY, 0, initSig.r, initSig.s);

      // Cancel with passkey
      const cancelOpHash = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["bytes4"],
          [ethers.dataSlice(ethers.keccak256(ethers.toUtf8Bytes("cancelRecovery")), 0, 4)]
        )
      );
      const cancelMsgHash = buildMessageHash(domainSep, cancelOpHash, 1n);
      const cancelSig = signP256(passkey.privateKey, cancelMsgHash);
      await wallet.cancelRecovery(cancelSig.r, cancelSig.s, 0);

      // Old passkey still works for execute
      const execOpHash = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["address", "uint256", "bytes"],
          [receiver.address, 0, "0x"]
        )
      );
      const execMsgHash = buildMessageHash(domainSep, execOpHash, 2n);
      const execSigs = signPasskey(passkey, execMsgHash);

      await expect(
        wallet.execute(receiver.address, 0, "0x", execSigs.passkeyR, execSigs.passkeyS)
      ).to.emit(wallet, "Executed");
    });
  });
});
