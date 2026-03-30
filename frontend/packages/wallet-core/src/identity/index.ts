import type { PasskeyProvider } from "../platform/index";
import type { SecureStorage } from "../platform/index";
import type { ApiClient } from "../api/index";
import type { GuardianClient } from "../guardian/index";
import type { IdentityStore } from "../state/index";
import {
  generateSecp256k1KeyPair,
  secp256k1AddressFromPublicKey,
  p256PublicKeyToXY,
  buildInitHash,
  buildInitializeCalldata,
  buildDomainSeparator,
  buildEIP712MessageHash,
  buildRotateOpHash,
  buildDeactivateOpHash,
  buildInitiateRecoveryOpHash,
  buildFinalizeRecoveryOpHash,
  signEIP7702AuthTuple,
  bytesToHex,
  hexToBytes,
  encodeFunctionCall,
  encodeUint256,
} from "../utils/index";

export interface OnboardingResult {
  did: string;
  eoaAddress: string;
  txHash: string;
}

export interface LoginResult {
  did: string;
  eoaAddress: string;
}

export class IdentityManager {
  constructor(
    private passkeyProvider: PasskeyProvider,
    private guardianClient: GuardianClient,
    private api: ApiClient,
    private identityStore: ReturnType<typeof import("../state/index").createIdentityStore>,
    private storage: SecureStorage,
    private config: {
      chainId: bigint;
      walletImplementationAddress: string;
    },
  ) {}

  /**
   * Full onboarding flow (spec section 2):
   * 1. Register with guardian server
   * 2. Create passkey
   * 3. Generate throwaway EOA
   * 4. Both keys sign init hash
   * 5. Submit 7702 delegation + initialize tx
   */
  async onboard(oauthToken: string): Promise<OnboardingResult | LoginResult> {
    // Step 1: Generate throwaway secp256k1 keypair → derive EOA address
    const throwawayKey = generateSecp256k1KeyPair();
    const eoaAddress = secp256k1AddressFromPublicKey(throwawayKey.publicKey);

    // Step 2: Register with guardian server → get recovery public key (or login if account exists)
    const onboardResult = await this.guardianClient.onboard(eoaAddress, oauthToken);

    // If the Google account already exists, this is a login on a new device
    if (onboardResult.type === "login") {
      const did = `did:sovra:${onboardResult.sovraAddress.toLowerCase()}`;
      const state = this.identityStore.getState();
      state.setLoginIdentity({
        did,
        eoaAddress: onboardResult.sovraAddress,
        chainId: this.config.chainId,
      });
      await state.persistToStorage(this.storage);
      return { did, eoaAddress: onboardResult.sovraAddress };
    }

    const { recoveryPublicKey } = onboardResult;

    // Step 3: Create passkey (biometric prompt)
    const passkey = await this.passkeyProvider.create("sovra-user", "Sovra Wallet");
    const passkeyXY = p256PublicKeyToXY(passkey.publicKey);

    // Step 4: Compute init hash matching SovraWalletV1.initialize()
    // (steps renumbered: EOA generated first so address is available for onboard)
    const initHash = buildInitHash(
      eoaAddress,
      this.config.chainId,
      passkeyXY.x,
      passkeyXY.y,
      recoveryPublicKey.x,
      recoveryPublicKey.y,
    );

    // Step 5: Sign init hash with passkey
    const passkeySig = await this.passkeyProvider.sign(
      passkey.credentialId,
      initHash,
    );
    // Extract r,s from the 64-byte signature
    const passkeyR = passkeySig.signature.slice(0, 32);
    const passkeyS = passkeySig.signature.slice(32, 64);

    // Step 6: Build initialize() calldata
    const initCalldata = buildInitializeCalldata(
      passkeyXY.x,
      passkeyXY.y,
      recoveryPublicKey.x,
      recoveryPublicKey.y,
      passkeyR,
      passkeyS,
    );

    // Step 7: Sign EIP-7702 authorization tuple with throwaway EOA key
    const authTuple = signEIP7702AuthTuple(
      throwawayKey.privateKey,
      this.config.chainId,
      this.config.walletImplementationAddress,
      0n, // nonce 0 for fresh EOA
    );

    // Step 8: Submit type-4 transaction
    const txHash = await this.api.sendTransaction({
      type: "0x04",
      authorizationList: [
        {
          chainId: "0x" + authTuple.chainId.toString(16),
          address: authTuple.address,
          nonce: "0x" + authTuple.nonce.toString(16),
          yParity: bytesToHex(new Uint8Array([authTuple.yParity])),
          r: authTuple.r,
          s: authTuple.s,
        },
      ],
      to: eoaAddress,
      data: bytesToHex(initCalldata),
      value: "0x0",
      gas: "0x100000",
    });

    // Step 9: Wait for receipt
    let receipt = null;
    for (let i = 0; i < 30; i++) {
      receipt = await this.api.getTransactionReceipt(txHash);
      if (receipt) break;
      await new Promise((r) => setTimeout(r, 2000));
    }
    if (!receipt) throw new Error("Transaction not confirmed");
    if (receipt.status !== "0x1") throw new Error("Transaction reverted");

    // Step 10: Persist identity (throwaway key is discarded by going out of scope)
    const did = `did:sovra:${eoaAddress.toLowerCase()}`;
    const state = this.identityStore.getState();
    state.setIdentity({
      did,
      eoaAddress,
      passkeyCredentialId: passkey.credentialId,
      passkeyPublicKey: passkey.publicKey,
      recoveryPublicKey,
      chainId: this.config.chainId,
    });
    await state.persistToStorage(this.storage);

    return { did, eoaAddress, txHash };
  }

  /** Rotate passkey — both current keys must sign. */
  async rotatePasskey(newPasskeyPublicKey: Uint8Array): Promise<string> {
    const state = this.identityStore.getState();
    if (!state.eoaAddress) throw new Error("Not onboarded");

    const { x: newX, y: newY } = p256PublicKeyToXY(newPasskeyPublicKey);
    const opHash = buildRotateOpHash("rotatePasskey", newX, newY);
    const domainSep = buildDomainSeparator(state.chainId!, state.eoaAddress);

    // Get current nonce from chain
    const nonceHex = await this.api.ethCall(
      state.eoaAddress,
      bytesToHex(
        encodeFunctionCall("nonce()", []),
      ),
    );
    const currentNonce = BigInt(nonceHex);

    const msgHash = buildEIP712MessageHash(domainSep, opHash, currentNonce);

    // Sign with current passkey
    const passkeySig = await this.passkeyProvider.sign(
      state.passkeyCredentialId!,
      msgHash,
    );
    const passkeyR = passkeySig.signature.slice(0, 32);
    const passkeyS = passkeySig.signature.slice(32, 64);

    const calldata = encodeFunctionCall(
      "rotatePasskey(bytes32,bytes32,bytes32,bytes32)",
      [newX, newY, passkeyR, passkeyS],
    );

    return this.api.sendTransaction({
      to: state.eoaAddress,
      data: bytesToHex(calldata),
      value: "0x0",
      gas: "0x100000",
    });
  }

  /** Rotate recovery key — server generates new key, passkey signs the on-chain rotation. */
  async rotateRecoveryKey(): Promise<string> {
    const state = this.identityStore.getState();
    if (!state.eoaAddress) throw new Error("Not onboarded");

    // Step 1: Server generates new recovery key and signs the rotation
    const result = await this.api.rotateRecoveryKey();

    const newX = hexToBytes(result.newRecoveryPublicKey.x);
    const newY = hexToBytes(result.newRecoveryPublicKey.y);

    // Step 2: Build the on-chain rotateRecoveryKey calldata with passkey signature
    const opHash = buildRotateOpHash("rotateRecoveryKey", newX, newY);
    const domainSep = buildDomainSeparator(state.chainId!, state.eoaAddress);

    const nonceHex = await this.api.ethCall(
      state.eoaAddress,
      bytesToHex(encodeFunctionCall("nonce()", [])),
    );
    const currentNonce = BigInt(nonceHex);

    const msgHash = buildEIP712MessageHash(domainSep, opHash, currentNonce);

    const passkeySig = await this.passkeyProvider.sign(
      state.passkeyCredentialId!,
      msgHash,
    );
    const passkeyR = passkeySig.signature.slice(0, 32);
    const passkeyS = passkeySig.signature.slice(32, 64);

    // Step 3: Submit the on-chain transaction
    const calldata = encodeFunctionCall(
      "rotateRecoveryKey(bytes32,bytes32,bytes32,bytes32)",
      [newX, newY, passkeyR, passkeyS],
    );

    const txHash = await this.api.sendTransaction({
      to: state.eoaAddress,
      data: bytesToHex(calldata),
      value: "0x0",
      gas: "0x100000",
    });

    // Step 4: Update local state with new recovery key
    state.setIdentity({
      did: state.did!,
      eoaAddress: state.eoaAddress!,
      passkeyCredentialId: state.passkeyCredentialId!,
      passkeyPublicKey: state.passkeyPublicKey!,
      recoveryPublicKey: { x: newX, y: newY },
      chainId: state.chainId!,
    });
    await state.persistToStorage(this.storage);

    return txHash;
  }

  /** Initiate passkey recovery — creates new passkey, server co-signs with recovery key. */
  async initiatePasskeyRecovery(): Promise<string> {
    const state = this.identityStore.getState();
    if (!state.eoaAddress) throw new Error("Not onboarded");

    // Step 1: Create a new passkey
    const newPasskey = await this.passkeyProvider.create("sovra-user", "Sovra Wallet");
    const { x: newX, y: newY } = p256PublicKeyToXY(newPasskey.publicKey);

    // Step 2: Send structured params to server — server constructs and signs the hash
    const response = await this.api.recoveryInitiate({
      newKeyX: bytesToHex(newX),
      newKeyY: bytesToHex(newY),
      keyToReplace: 0,
    });
    const sigR = hexToBytes(response.signature.r);
    const sigS = hexToBytes(response.signature.s);

    // Step 4: Build initiateRecovery calldata
    const calldata = encodeFunctionCall(
      "initiateRecovery(bytes32,bytes32,uint8,bytes32,bytes32)",
      [newX, newY, encodeUint256(0n), sigR, sigS],
    );

    // Step 5: Submit tx
    const txHash = await this.api.sendTransaction({
      to: state.eoaAddress,
      data: bytesToHex(calldata),
      value: "0x0",
      gas: "0x100000",
    });

    // Step 6: Wait for receipt
    let receipt = null;
    for (let i = 0; i < 30; i++) {
      receipt = await this.api.getTransactionReceipt(txHash);
      if (receipt) break;
      await new Promise((r) => setTimeout(r, 2000));
    }
    if (!receipt) throw new Error("Transaction not confirmed");
    if (receipt.status !== "0x1") throw new Error("Transaction reverted");

    // Step 7: Store pending recovery state
    state.setPendingRecovery({
      passkeyCredentialId: newPasskey.credentialId,
      passkeyPublicKey: newPasskey.publicKey,
      initiatedAt: Date.now(),
    });
    await state.persistToStorage(this.storage);

    return txHash;
  }

  /** Check for pending recovery and finalize if 7+ days have passed. */
  async checkAndFinalizeRecovery(): Promise<boolean> {
    const state = this.identityStore.getState();
    if (!state.eoaAddress || !state.pendingRecovery) return false;

    const SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000;
    if (Date.now() - state.pendingRecovery.initiatedAt < SEVEN_DAYS_MS) return false;

    // Step 1: Server constructs the hash and signs it
    const response = await this.api.recoveryFinalize();
    const sigR = hexToBytes(response.signature.r);
    const sigS = hexToBytes(response.signature.s);

    // Step 3: Build finalizeRecovery calldata
    const calldata = encodeFunctionCall(
      "finalizeRecovery(bytes32,bytes32)",
      [sigR, sigS],
    );

    // Step 3: Submit tx
    const txHash = await this.api.sendTransaction({
      to: state.eoaAddress,
      data: bytesToHex(calldata),
      value: "0x0",
      gas: "0x100000",
    });

    // Step 4: Wait for receipt
    let receipt = null;
    for (let i = 0; i < 30; i++) {
      receipt = await this.api.getTransactionReceipt(txHash);
      if (receipt) break;
      await new Promise((r) => setTimeout(r, 2000));
    }
    if (!receipt) throw new Error("Transaction not confirmed");
    if (receipt.status !== "0x1") throw new Error("Transaction reverted");

    // Step 5: Update identity with new passkey
    state.setIdentity({
      did: state.did!,
      eoaAddress: state.eoaAddress,
      passkeyCredentialId: state.pendingRecovery.passkeyCredentialId,
      passkeyPublicKey: state.pendingRecovery.passkeyPublicKey,
      recoveryPublicKey: state.recoveryPublicKey!,
      chainId: state.chainId!,
    });
    state.clearPendingRecovery();
    await state.persistToStorage(this.storage);

    return true;
  }

  /** Deactivate DID permanently — both keys sign. */
  async deactivate(): Promise<string> {
    const state = this.identityStore.getState();
    if (!state.eoaAddress) throw new Error("Not onboarded");

    const opHash = buildDeactivateOpHash();
    const domainSep = buildDomainSeparator(state.chainId!, state.eoaAddress);

    const nonceHex = await this.api.ethCall(
      state.eoaAddress,
      bytesToHex(encodeFunctionCall("nonce()", [])),
    );
    const currentNonce = BigInt(nonceHex);

    const msgHash = buildEIP712MessageHash(domainSep, opHash, currentNonce);

    const passkeySig = await this.passkeyProvider.sign(
      state.passkeyCredentialId!,
      msgHash,
    );
    const passkeyR = passkeySig.signature.slice(0, 32);
    const passkeyS = passkeySig.signature.slice(32, 64);

    const calldata = encodeFunctionCall(
      "deactivate(bytes32,bytes32)",
      [passkeyR, passkeyS],
    );

    return this.api.sendTransaction({
      to: state.eoaAddress,
      data: bytesToHex(calldata),
      value: "0x0",
      gas: "0x100000",
    });
  }
}
