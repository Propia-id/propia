import type { IssuerKeyData, HolderKeyData } from "./types";

const TRUST_TTL_MS = 5 * 60 * 1000; // 5 minutes
const MAX_CACHE_SIZE = 200;

interface CachedValue<T> {
  data: T;
  versionId: number;
}

interface TrustCacheEntry {
  trusted: boolean;
  fetchedAt: number;
}

export class VerificationCache {
  private issuerKeys = new Map<string, CachedValue<IssuerKeyData>>();
  private holderKeys = new Map<string, CachedValue<HolderKeyData>>();
  private issuerTrust = new Map<string, TrustCacheEntry>();

  getIssuerKeys(address: string): IssuerKeyData | null {
    const entry = this.issuerKeys.get(address.toLowerCase());
    return entry?.data ?? null;
  }

  setIssuerKeys(address: string, data: IssuerKeyData): void {
    this.evictIfNeeded(this.issuerKeys);
    this.issuerKeys.set(address.toLowerCase(), {
      data,
      versionId: data.versionId,
    });
  }

  getHolderKeys(address: string): HolderKeyData | null {
    const entry = this.holderKeys.get(address.toLowerCase());
    return entry?.data ?? null;
  }

  setHolderKeys(address: string, data: HolderKeyData): void {
    this.evictIfNeeded(this.holderKeys);
    this.holderKeys.set(address.toLowerCase(), {
      data,
      versionId: data.versionId,
    });
  }

  getIssuerTrust(issuer: string, typeId: string): boolean | null {
    const key = `${issuer.toLowerCase()}:${typeId}`;
    const entry = this.issuerTrust.get(key);
    if (!entry) return null;
    if (Date.now() - entry.fetchedAt > TRUST_TTL_MS) {
      this.issuerTrust.delete(key);
      return null;
    }
    return entry.trusted;
  }

  setIssuerTrust(issuer: string, typeId: string, trusted: boolean): void {
    this.evictIfNeeded(this.issuerTrust);
    const key = `${issuer.toLowerCase()}:${typeId}`;
    this.issuerTrust.set(key, { trusted, fetchedAt: Date.now() });
  }

  private evictIfNeeded<K, V>(map: Map<K, V>): void {
    if (map.size >= MAX_CACHE_SIZE) {
      const firstKey = map.keys().next().value;
      if (firstKey !== undefined) map.delete(firstKey);
    }
  }

  clear(): void {
    this.issuerKeys.clear();
    this.holderKeys.clear();
    this.issuerTrust.clear();
  }
}
