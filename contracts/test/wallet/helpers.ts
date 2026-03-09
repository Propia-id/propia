import { ethers, network } from "hardhat";
import { p256 } from "@noble/curves/p256";
import { keccak_256 } from "@noble/hashes/sha3";

// ─── P256 Key Helpers ────────────────────────────────────

export interface P256KeyPair {
  privateKey: Uint8Array;
  publicKeyX: string; // bytes32 hex
  publicKeyY: string; // bytes32 hex
}

export function generateP256KeyPair(): P256KeyPair {
  const privateKey = p256.utils.randomPrivateKey();
  const publicKey = p256.getPublicKey(privateKey, false); // uncompressed: 04 || x || y
  const publicKeyX = "0x" + Buffer.from(publicKey.slice(1, 33)).toString("hex");
  const publicKeyY = "0x" + Buffer.from(publicKey.slice(33, 65)).toString("hex");
  return { privateKey, publicKeyX, publicKeyY };
}

export interface P256Signature {
  r: string; // bytes32 hex
  s: string; // bytes32 hex
}

export function signP256(privateKey: Uint8Array, hash: string): P256Signature {
  // Remove 0x prefix and convert to Uint8Array
  const hashBytes = Uint8Array.from(Buffer.from(hash.slice(2), "hex"));
  const sig = p256.sign(hashBytes, privateKey, { lowS: true });
  const r = "0x" + sig.r.toString(16).padStart(64, "0");
  const s = "0x" + sig.s.toString(16).padStart(64, "0");
  return { r, s };
}

// ─── EIP-712 Helpers ─────────────────────────────────────

const DOMAIN_TYPEHASH = ethers.keccak256(
  ethers.toUtf8Bytes("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
);
const NAME_HASH = ethers.keccak256(ethers.toUtf8Bytes("SovraWallet"));
const VERSION_HASH = ethers.keccak256(ethers.toUtf8Bytes("1"));

export function buildDomainSeparator(chainId: bigint, walletAddress: string): string {
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32", "bytes32", "uint256", "address"],
      [DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, chainId, walletAddress]
    )
  );
}

export function buildMessageHash(domainSep: string, operationHash: string, nonce: bigint): string {
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32", "uint256"],
      [domainSep, operationHash, nonce]
    )
  );
}

// ─── Deploy Helpers ──────────────────────────────────────

export async function etchP256Verifier() {
  // Deploy P256Verifier contract to get its runtime bytecode
  const P256Verifier = await ethers.getContractFactory("P256Verifier");
  const verifier = await P256Verifier.deploy();
  await verifier.waitForDeployment();
  const deployedCode = await ethers.provider.getCode(await verifier.getAddress());

  // Etch at 0x0100 (EIP-7212 precompile address)
  await network.provider.send("hardhat_setCode", [
    "0x0000000000000000000000000000000000000100",
    deployedCode,
  ]);
}

export async function deployWallet() {
  await etchP256Verifier();

  const SovraWalletV1 = await ethers.getContractFactory("SovraWalletV1");
  const implementation = await SovraWalletV1.deploy();
  await implementation.waitForDeployment();

  const SovraDispatcher = await ethers.getContractFactory("SovraDispatcher");
  const dispatcher = await SovraDispatcher.deploy(await implementation.getAddress());
  await dispatcher.waitForDeployment();

  // Get wallet interface through dispatcher
  const wallet = SovraWalletV1.attach(await dispatcher.getAddress()) as typeof implementation;

  return { wallet, dispatcher, implementation };
}

export async function deployAndInitialize() {
  const { wallet, dispatcher, implementation } = await deployWallet();

  const passkey = generateP256KeyPair();
  const serverKey = generateP256KeyPair();

  const walletAddress = await wallet.getAddress();
  const chainId = (await ethers.provider.getNetwork()).chainId;
  const domainSep = buildDomainSeparator(chainId, walletAddress);

  // Build init hash: keccak256(abi.encode(address(this), passkeyX, passkeyY, serverKeyX, serverKeyY))
  const initHash = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["address", "bytes32", "bytes32", "bytes32", "bytes32"],
      [walletAddress, passkey.publicKeyX, passkey.publicKeyY, serverKey.publicKeyX, serverKey.publicKeyY]
    )
  );

  const passkeySig = signP256(passkey.privateKey, initHash);
  const serverSig = signP256(serverKey.privateKey, initHash);

  await wallet.initialize(
    passkey.publicKeyX, passkey.publicKeyY,
    serverKey.publicKeyX, serverKey.publicKeyY,
    passkeySig.r, passkeySig.s,
    serverSig.r, serverSig.s
  );

  return {
    wallet,
    dispatcher,
    implementation,
    passkey,
    serverKey,
    domainSep,
    walletAddress,
    chainId,
  };
}

// ─── Signing Helpers ─────────────────────────────────────

export function sign2of2(
  passkey: P256KeyPair,
  serverKey: P256KeyPair,
  msgHash: string
): { passkeyR: string; passkeyS: string; serverR: string; serverS: string } {
  const passkeySig = signP256(passkey.privateKey, msgHash);
  const serverSig = signP256(serverKey.privateKey, msgHash);
  return {
    passkeyR: passkeySig.r,
    passkeyS: passkeySig.s,
    serverR: serverSig.r,
    serverS: serverSig.s,
  };
}
