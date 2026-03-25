// sdk/typescript/src/registry.ts

import type { RegistryManifest, RevocationList, VerificationResult } from './types';
import { verifyAttestation } from './verify';
import { OpenAgentTrustRegistryError, verifyRegistryArtifacts } from './registry-artifacts';

export class OpenAgentTrustRegistry {
  private mirrorUrl: string;
  private manifest: RegistryManifest | null = null;
  private revocations: RevocationList | null = null;
  private lastFetchTime: number = 0;
  
  // Refresh cache every 15 minutes by default
  private readonly CACHE_TTL_MS = 15 * 60 * 1000; 

  private constructor(mirrorUrl: string) {
    this.mirrorUrl = mirrorUrl;
  }

  /**
   * Initialize a new Registry Client and fetch the initial state.
   */
  public static async load(mirrorUrl: string): Promise<OpenAgentTrustRegistry> {
    const registry = new OpenAgentTrustRegistry(mirrorUrl.replace(/\/$/, ''));
    await registry.refresh();
    return registry;
  }

  /**
   * Manually trigger a refresh of the cached registry state from the network.
   */
  public async refresh(): Promise<void> {
    try {
      const [manifestRes, revocationsRes] = await Promise.all([
        fetch(`${this.mirrorUrl}/v1/registry`),
        fetch(`${this.mirrorUrl}/v1/revocations`)
      ]);

      if (!manifestRes.ok || !revocationsRes.ok) {
        throw new OpenAgentTrustRegistryError(
          'fetch_failed',
          `Failed to fetch registry state: ${manifestRes.status} / ${revocationsRes.status}`
        );
      }

      const manifest = await manifestRes.json();
      const revocations = await revocationsRes.json();
      const verifiedState = verifyRegistryArtifacts(manifest, revocations);

      this.manifest = verifiedState.manifest;
      this.revocations = verifiedState.revocations;
      this.lastFetchTime = Date.now();

    } catch (err) {
      console.error('[OpenAgentTrustRegistry] Failed to refresh state', err);
      throw err;
    }
  }

  /**
   * Verify an incoming agent attestation JWS token locally against the loaded registry state.
   * 
   * @param attestationJws The raw string JWS token
   * @param expectedAudience The specific service origin (aud) expecting this token
   * @param expectedNonce Optional nonce if the service requires intra-service replay protection
   */
  public async verifyToken(
    attestationJws: string, 
    expectedAudience: string,
    expectedNonce?: string
  ): Promise<VerificationResult> {
    
    // Auto-refresh if cache is stale
    if (Date.now() - this.lastFetchTime > this.CACHE_TTL_MS) {
        await this.refresh();
    }

    if (!this.manifest || !this.revocations) {
        throw new OpenAgentTrustRegistryError('registry_not_loaded', 'Registry state not loaded');
    }

    const verifiedState = verifyRegistryArtifacts(this.manifest, this.revocations);
    this.manifest = verifiedState.manifest;
    this.revocations = verifiedState.revocations;

    return verifyAttestation(
        attestationJws, 
        this.manifest, 
        this.revocations, 
        expectedAudience, 
        expectedNonce
    );
  }
}
