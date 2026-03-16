import { SignJWT } from 'jose';
import { readFile } from 'fs/promises';
import { resolve } from 'path';
import { createPrivateKey } from 'crypto';

export const issue = async (options: {
    issuerId: string;
    kid: string;
    privateKey: string;
    audience: string;
    scope: string;
    expiresIn: number;
}) => {
    try {
        console.log('[1/3] Loading Ed25519 private key...');
        const keyPath = resolve(process.cwd(), options.privateKey);
        const privateKeyB64 = await readFile(keyPath, 'utf-8');
        const privateKeyBytes = Buffer.from(privateKeyB64.trim(), 'base64url');
        const seedHex = privateKeyBytes.subarray(0, 32).toString('hex');
        
        console.log('[2/3] Preparing agent-attestation+jwt payload...');
        const now = Math.floor(Date.now() / 1000);
        
        const payload = {
            sub: 'agent-instance-' + crypto.randomUUID().slice(0, 8),
            aud: options.audience,
            iat: now,
            nonce: crypto.randomUUID(),
            scope: options.scope.split(',').map(s => s.trim()),
            constraints: {
                time_bound: true
            },
            user_pseudonym: 'pairwise-' + crypto.randomUUID().slice(0, 8),
            runtime_version: '1.0.0'
        };

        console.log('[3/3] Signing EdDSA attestation token...');
        
        // Wrap the raw 32-byte Ed25519 seed in a PKCS#8 DER ASN.1 structure
        // 302e020100300506032b657004220420 is the standard ASN.1 prefix for Ed25519 private keys
        const pkcs8Der = Buffer.from('302e020100300506032b657004220420' + seedHex, 'hex');
        const privateKeyObj = createPrivateKey({
            key: pkcs8Der,
            format: 'der',
            type: 'pkcs8'
        });

        const jwt = await new SignJWT(payload)
            .setProtectedHeader({
                alg: 'EdDSA',
                kid: options.kid,
                iss: options.issuerId,
                typ: 'agent-attestation+jwt'
            })
            .setExpirationTime(now + options.expiresIn)
            .sign(privateKeyObj);

        console.log('\n✓ Test Attestation Generated Successfully:');
        console.log('--------------------------------------------------');
        console.log(jwt);
        console.log('--------------------------------------------------');
        console.log(`\nTo test verification, copy the string above and run:\nagent-trust verify <TOKEN> --audience ${options.audience}`);
        
    } catch (err) {
        if (err instanceof Error) {
            console.error('\n❌ Failed to generate test attestation:', err.message);
        } else {
            console.error('\n❌ An unexpected error occurred while generating the test attestation.');
        }
        process.exit(1);
    }
};
