import type { PasskeyProvider } from "../platform/index";
import type { SecureStorage } from "../platform/index";
import type { ApiClient } from "../api/index";
import type { CosignerClient } from "../cosigner/index";
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
  signEIP7702AuthTuple,
  bytesToHex,
  hexToBytes,
  encodeFunctionCall,
} from "../utils/index";

export interface OnboardingResult {
  did: string;
  eoaAddress: string;
  txHash: string;
}

export class IdentityManager {
  constructor(
    private passkeyProvider: PasskeyProvider,
    private cosignerClient: CosignerClient,
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
   * 1. Register with co-signing server
   * 2. Create passkey
   * 3. Generate throwaway EOA
   * 4. Both keys sign init hash
   * 5. Submit 7702 delegation + initialize tx
   */
  async onboard(oauthToken: string): Promise<OnboardingResult> {
    // Step 1: Generate throwaway secp256k1 keypair → derive EOA address
    const throwawayKey = generateSecp256k1KeyPair();
    const eoaAddress = secp256k1AddressFromPublicKey(throwawayKey.publicKey);

    // Step 2: Register with co-signing server → get server public key
    const { serverPublicKey } = await this.cosignerClient.onboard(eoaAddress, oauthToken);

    // Step 3: Create passkey (biometric prompt)
    const passkey = await this.passkeyProvider.create("sovra-user", "Sovra Wallet");
    const passkeyXY = p256PublicKeyToXY(passkey.publicKey);

    // Step 4: Compute init hash matching SovraWalletV1.initialize()
    // (steps renumbered: EOA generated first so address is available for onboard)
    const initHash = buildInitHash(
      eoaAddress,
      passkeyXY.x,
      passkeyXY.y,
      serverPublicKey.x,
      serverPublicKey.y,
    );

    // Step 5: Sign init hash with passkey
    const passkeySig = await this.passkeyProvider.sign(
      passkey.credentialId,
      initHash,
    );
    // Extract r,s from the 64-byte signature
    const passkeyR = passkeySig.signature.slice(0, 32);
    const passkeyS = passkeySig.signature.slice(32, 64);

    // Step 6: Co-sign init hash with server
    const serverSig = await this.cosignerClient.cosign(initHash);

    // Step 7: Build initialize() calldata
    const initCalldata = buildInitializeCalldata(
      passkeyXY.x,
      passkeyXY.y,
      serverPublicKey.x,
      serverPublicKey.y,
      passkeyR,
      passkeyS,
      serverSig.r,
      serverSig.s,
    );

    // Step 8: Sign EIP-7702 authorization tuple with throwaway EOA key
    const authTuple = signEIP7702AuthTuple(
      throwawayKey.privateKey,
      this.config.chainId,
      this.config.walletImplementationAddress,
      0n, // nonce 0 for fresh EOA
    );

    // Step 9: Submit type-4 transaction
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

    // Step 10: Wait for receipt
    let receipt = null;
    for (let i = 0; i < 30; i++) {
      receipt = await this.api.getTransactionReceipt(txHash);
      if (receipt) break;
      await new Promise((r) => setTimeout(r, 2000));
    }
    if (!receipt) throw new Error("Transaction not confirmed");
    if (receipt.status !== "0x1") throw new Error("Transaction reverted");

    // Step 11: Persist identity (throwaway key is discarded by going out of scope)
    const did = `did:sovra:${eoaAddress.toLowerCase()}`;
    const state = this.identityStore.getState();
    state.setIdentity({
      did,
      eoaAddress,
      passkeyCredentialId: passkey.credentialId,
      passkeyPublicKey: passkey.publicKey,
      serverPublicKey,
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

    // Co-sign with server
    const serverSig = await this.cosignerClient.cosign(msgHash);

    const calldata = encodeFunctionCall(
      "rotatePasskey(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32)",
      [newX, newY, passkeyR, passkeyS, serverSig.r, serverSig.s],
    );

    return this.api.sendTransaction({
      to: state.eoaAddress,
      data: bytesToHex(calldata),
      value: "0x0",
      gas: "0x100000",
    });
  }

  /** Rotate server key — both current keys must sign. */
  async rotateServerKey(): Promise<string> {
    // Server generates new key; this triggers the co-signing server's rotation endpoint
    throw new Error("Not implemented — requires POST /rotate-server-key endpoint");
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

    const serverSig = await this.cosignerClient.cosign(msgHash);

    const calldata = encodeFunctionCall(
      "deactivate(bytes32,bytes32,bytes32,bytes32)",
      [passkeyR, passkeyS, serverSig.r, serverSig.s],
    );

    return this.api.sendTransaction({
      to: state.eoaAddress,
      data: bytesToHex(calldata),
      value: "0x0",
      gas: "0x100000",
    });
  }
}
