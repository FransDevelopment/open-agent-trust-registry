// sdk/typescript/src/types/attestation.ts

/**
 * Domain-agnostic generic constraints record. 
 * The specific key-value pairs are arbitrarily negotiated between the agent and service 
 * (e.g. max_cost_usd for payments, allowed_tables for databases, etc.)
 */
export type AgnosticConstraints = Record<string, unknown>;

export interface AttestationClaims {
  /** Agent instance identifier */
  sub: string;
  
  /** Target service origin */
  aud: string;
  
  /** Issued at timestamp (seconds) */
  iat: number;
  
  /** Expiry timestamp (seconds) */
  exp: number;
  
  /** Service-provided nonce preventing intra-service replay */
  nonce?: string;
  
  /** Array of authorized scopes */
  scope: string[];
  
  /** Domain-agnostic structured constraints */
  constraints: AgnosticConstraints;
  
  /** Pairwise pseudonymous identifier */
  user_pseudonym: string;
  
  /** Version of the issuing runtime */
  runtime_version: string;
}

export interface VerificationResult {
  valid: boolean;
  reason?: 'unknown_issuer' | 'revoked_issuer' | 'unknown_key' | 'revoked_key' | 'expired_attestation' | 'invalid_signature' | 'audience_mismatch' | 'nonce_mismatch';
  issuer?: import('./registry').IssuerEntry;
  claims?: AttestationClaims;
}
