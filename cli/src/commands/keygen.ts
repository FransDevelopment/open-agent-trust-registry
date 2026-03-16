import * as ed from '@noble/ed25519';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

// Polyfill for noble in raw node environments
if (!globalThis.crypto) {
    globalThis.crypto = crypto.webcrypto as any;
}

export const keygen = async (options: { issuerId: string; outDir: string }) => {
    try {
        console.log(`Generating Ed25519 keypair for issuer '${options.issuerId}'...\n`);

        const privateKeyRaw = ed.utils.randomSecretKey();
        const publicKeyRaw = await ed.getPublicKeyAsync(privateKeyRaw);

        const privateKeyBase64Url = Buffer.from(privateKeyRaw).toString('base64url');
        const publicKeyBase64Url = Buffer.from(publicKeyRaw).toString('base64url');

        // Create the kid (Key ID) using a stable date prefix
        const dateStr = new Date().toISOString().substring(0, 7); // e.g., 2026-03
        const kid = `${options.issuerId}-${dateStr}`;

        // Save private key
        const privateKeyPath = path.join(options.outDir, `${options.issuerId}.key`);
        fs.writeFileSync(privateKeyPath, privateKeyBase64Url, { mode: 0o600 });

        console.log(`✅ Success!`);
        console.log(`🔑 Private Key saved to: ${privateKeyPath} (Keep this strictly secret)`);
        console.log(`\nPublic Key Details for Registration:`);
        console.log(`-------------------------------------`);
        console.log(`KID:        ${kid}`);
        console.log(`Algorithm:  Ed25519`);
        console.log(`Public Key: ${publicKeyBase64Url}`);
        console.log(`-------------------------------------`);
        console.log(`\nYou may now run 'agent-trust register' to scaffold your formal JSON entry.`);
        
    } catch (err) {
        console.error('Failed to generate keypair:', err);
        process.exit(1);
    }
};
