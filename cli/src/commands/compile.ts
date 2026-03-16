import { readdir, readFile, writeFile } from 'fs/promises';
import { join } from 'path';
import * as ed from '@noble/ed25519';

export async function compile(options: { privateKey: string }) {
    try {
        console.log('Compiling registry manifest...');
        
        const registryDir = join(process.cwd(), '../registry');
        const issuersDir = join(registryDir, 'issuers');
        const files = await readdir(issuersDir);
        
        const issuers: Record<string, any> = {};
        
        for (const file of files) {
            if (file.endsWith('.json')) {
                const content = await readFile(join(issuersDir, file), 'utf8');
                const parsed = JSON.parse(content);
                issuers[parsed.issuer_id] = parsed;
            }
        }

        const timestamp = new Date().toISOString();
        const expires = new Date(Date.now() + 60 * 60 * 1000).toISOString(); // +1 hour
        
        const manifest = {
            version: "1.0",
            generated_at: timestamp,
            expires_at: expires,
            total_issuers: Object.keys(issuers).length,
            issuers: issuers,
            signature: ""
        };

        const payloadToSign = JSON.stringify({
            version: manifest.version,
            generated_at: manifest.generated_at,
            expires_at: manifest.expires_at,
            total_issuers: manifest.total_issuers,
            issuers: manifest.issuers
        });

        const privateKeyBuffer = Buffer.from(options.privateKey, 'base64url');
        if (privateKeyBuffer.length !== 32) {
            throw new Error("Invalid private key length. Must be 32 bytes (base64url encoded).");
        }
        
        // Use async signing to avoid needing the sync sha512 configuration
        const signatureBytes = await ed.signAsync(Buffer.from(payloadToSign, 'utf8'), privateKeyBuffer);
        const signatureStr = Buffer.from(signatureBytes).toString('base64url');

        manifest.signature = `ed25519:${signatureStr}`;
        
        const outputPath = join(registryDir, 'manifest.json');
        await writeFile(outputPath, JSON.stringify(manifest, null, 2));

        console.log('✅ Success!');
        console.log(`Signed Manifest saved to: ${outputPath}`);
        console.log(`Total Issuers: ${manifest.total_issuers}`);

    } catch (error: any) {
        console.error('❌ Failed to compile registry:', error.message);
        process.exit(1);
    }
}
