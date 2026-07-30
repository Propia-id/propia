import { ethers } from "hardhat";
import type { BaseContract, Signer } from "ethers";
import { REGISTRY_NAMES, RegistryName } from "./chain-config";
import { AccessControlReader, AccessControlWriter, Registries } from "./roles";

/// Hardhat-side glue: turns registry contracts into the read/write handles the
/// role functions take.

/// Pairs each contract with a provider-connected instance for its view calls;
/// the signer-connected one is kept for transactions. See RegistryHandle in
/// roles.ts for why reads cannot go through the signer.
export function toRegistries(contracts: Record<RegistryName, BaseContract>): Registries {
  const handles = {} as Registries;
  for (const name of REGISTRY_NAMES) {
    handles[name] = {
      read: contracts[name].connect(ethers.provider) as unknown as AccessControlReader,
      write: contracts[name] as unknown as AccessControlWriter,
    };
  }
  return handles;
}

/// Attaches to already-deployed registries, e.g. to finish the role step of a
/// deployment that got that far.
export async function attachRegistries(
  addresses: Record<RegistryName, string>,
  signer: Signer
): Promise<Registries> {
  const contracts = {} as Record<RegistryName, BaseContract>;
  for (const name of REGISTRY_NAMES) {
    contracts[name] = await ethers.getContractAt(name, addresses[name], signer);
  }
  return toRegistries(contracts);
}
