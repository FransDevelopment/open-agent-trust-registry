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
        console.log(`\nGenerating Ed25519 keypair for issuer '${options.issuerId}'...\n`);

        const privateKeyRaw = ed.utils.randomSecretKey();
        const publicKeyRaw = await ed.getPublicKeyAsync(privateKeyRaw);

        const privateKeyBase64Url = Buffer.from(privateKeyRaw).toString('base64url');
        const publicKeyBase64Url = Buffer.from(publicKeyRaw).toString('base64url');

        // Create the kid (Key ID) using a stable date prefix
        const dateStr = new Date().toISOString().substring(0, 7); // e.g., 2026-03
        const kid = `${options.issuerId}-${dateStr}`;

        // Industry standard .pem extension with 'private' in filename for clarity
        const privateKeyPath = path.join(options.outDir, `${options.issuerId}.private.pem`);
        fs.writeFileSync(privateKeyPath, privateKeyBase64Url, { mode: 0o600 });

        console.log(`✅ Keypair generated successfully!\n`);
        console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
        console.log(`  Private Key: ${privateKeyPath}`);
        console.log(`  KID:         ${kid}`);
        console.log(`  Algorithm:   Ed25519`);
        console.log(`  Public Key:  ${publicKeyBase64Url}`);
        console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`);

        console.log(`⚠️  Keep your private key secret. Never commit it to a repo.\n`);
        console.log(`   To view it:   cat ${privateKeyPath}`);
        console.log(`   To secure it: chmod 600 ${privateKeyPath}\n`);
        console.log(`   Note: Do not double-click the .pem file. On macOS, this opens`);
        console.log(`   Keychain Access. Always use 'cat' or a text editor from the terminal.\n`);
        console.log(`Next steps:\n`);
        console.log(`  1. Add your public key to your agent.json for Tier 3 identity:\n`);
        console.log(`     "identity": {`);
        console.log(`       "did": "did:web:yourdomain.com",`);
        console.log(`       "public_key": "${publicKeyBase64Url}"`);
        console.log(`     }\n`);
        console.log(`  2. Host a DID document at https://yourdomain.com/.well-known/did.json`);
        console.log(`     (See docs: https://agentinternetruntime.com/spec/agent-json#becoming-tier-3)\n`);
        console.log(`  3. To register as a trusted runtime issuer in the Trust Registry:`);
        console.log(`     npx @open-agent-trust/cli register --issuer-id ${options.issuerId} \\`);
        console.log(`       --display-name "Your Display Name" --website https://yourdomain.com \\`);
        console.log(`       --contact security@yourdomain.com --public-key ${publicKeyBase64Url}\n`);

    } catch (err) {
        console.error('Failed to generate keypair:', err);
        process.exit(1);
    }
};
