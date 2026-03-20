import * as fs from 'fs';
import * as path from 'path';

interface RegisterOptions {
    issuerId: string;
    displayName: string;
    website: string;
    contact: string;
    publicKey: string;
    outFile?: string;
}

export const register = async (options: RegisterOptions) => {
    
    const nowISO = new Date().toISOString();
    
    // Hardcoded to standard generic capabilities for Phase 1 scaffolding.
    // Real users would edit this draft JSON file.
    let entry = {
        "issuer_id": options.issuerId,
        "display_name": options.displayName,
        "website": options.website,
        "security_contact": options.contact,
        "status": "active",
        "added_at": nowISO,
        "last_verified": nowISO,
        "public_keys": [
            {
                "kid": `${options.issuerId}-${nowISO.substring(0,7)}`,
                "algorithm": "Ed25519",
                "public_key": options.publicKey,
                "status": "active",
                "issued_at": nowISO,
                "expires_at": new Date(Date.now() + 31536000000).toISOString(), // +1 year
                "deprecated_at": null,
                "revoked_at": null
            }
        ],
        "capabilities": {
            "supervision_model": "tiered",
            "audit_logging": true,
            "immutable_audit": false,
            "attestation_format": "jwt",
            "max_attestation_ttl_seconds": 3600,
            "capabilities_verified": false
        }
    };

    const outPath = options.outFile || path.join(process.cwd(), `${options.issuerId}.json`);
    
    fs.writeFileSync(outPath, JSON.stringify(entry, null, 2));

    console.log(`✅ Draft Issuer Entry generated at: ${outPath}`);
    console.log(`\nPlease review the \"capabilities\" block to ensure it matches your runtime's exact profile.`);
    console.log(`When ready, submit this file as a Pull Request to 'registry/issuers/' in the open source repository.`);
};
