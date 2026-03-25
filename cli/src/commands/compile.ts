import { readdir, readFile, writeFile } from 'fs/promises';
import { join } from 'path';
import { resolve } from 'path';
import { resolveActiveRootKey, signRegistryArtifact } from '../lib/registry-artifacts';

export async function compile(options: { privateKey: string }) {
    try {
        console.log('Compiling registry manifest...');
        
        const registryDir = join(process.cwd(), '../registry');
        const issuersDir = join(registryDir, 'issuers');
        const files = await readdir(issuersDir);
        const entries: Record<string, any>[] = [];
        
        for (const file of files) {
            if (file.endsWith('.json')) {
                const content = await readFile(join(issuersDir, file), 'utf8');
                const parsed = JSON.parse(content);
                entries.push(parsed);
            }
        }

        entries.sort((a, b) => a.issuer_id.localeCompare(b.issuer_id));

        const timestamp = new Date().toISOString();
        const manifestExpiry = new Date(Date.now() + 60 * 60 * 1000).toISOString();
        const revocationExpiry = new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString();

        const privateKeyPath = resolve(process.cwd(), options.privateKey);
        const privateSeed = (await readFile(privateKeyPath, 'utf8')).trim();
        const rootKey = await resolveActiveRootKey(registryDir, privateSeed);

        const unsignedManifest = {
            schema_version: '1.0.0',
            registry_id: 'open-trust-registry',
            generated_at: timestamp,
            expires_at: manifestExpiry,
            entries
        };

        const manifest = {
            ...unsignedManifest,
            signature: await signRegistryArtifact(unsignedManifest, privateSeed, rootKey.kid)
        };

        const revocationsPath = join(registryDir, 'revocations.json');
        const currentRevocations = JSON.parse(await readFile(revocationsPath, 'utf8'));
        const unsignedRevocations = {
            schema_version: currentRevocations.schema_version ?? '1.0.0',
            generated_at: timestamp,
            expires_at: revocationExpiry,
            revoked_keys: currentRevocations.revoked_keys ?? [],
            revoked_issuers: currentRevocations.revoked_issuers ?? []
        };
        const revocations = {
            ...unsignedRevocations,
            signature: await signRegistryArtifact(unsignedRevocations, privateSeed, rootKey.kid)
        };
        
        const outputPath = join(registryDir, 'manifest.json');
        await writeFile(outputPath, JSON.stringify(manifest, null, 2));
        await writeFile(revocationsPath, JSON.stringify(revocations, null, 2));

        console.log('✅ Success!');
        console.log(`Signed Manifest saved to: ${outputPath}`);
        console.log(`Signed Revocations saved to: ${revocationsPath}`);
        console.log(`Total Issuers: ${manifest.entries.length}`);

    } catch (error: any) {
        console.error('❌ Failed to compile registry:', error.message);
        process.exit(1);
    }
}
