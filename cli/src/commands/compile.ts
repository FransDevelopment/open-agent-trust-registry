import { readdir, readFile, writeFile } from 'fs/promises';
import { join } from 'path';
import { resolve } from 'path';
import { resolveActiveRootKey, signRegistryArtifact } from '../lib/registry-artifacts';

const GRACE_PERIOD_MS = 90 * 24 * 60 * 60 * 1000;

function validateEntries(entries: Record<string, any>[]): number {
    let warnings = 0;
    const now = Date.now();

    for (const entry of entries) {
        const issuerId = entry.issuer_id ?? 'unknown';
        const keys: any[] = entry.public_keys ?? [];
        let activeKeyCount = 0;

        for (const key of keys) {
            const kid = key.kid ?? 'unknown';

            // Expired key still in manifest
            if (key.expires_at && new Date(key.expires_at).getTime() < now) {
                console.warn(`  ⚠ ${issuerId}/${kid}: key has expired (expires_at: ${key.expires_at})`);
                warnings++;
            }

            // Deprecated key past grace period
            if (key.status === 'deprecated' && key.deprecated_at) {
                const elapsed = now - new Date(key.deprecated_at).getTime();
                if (elapsed > GRACE_PERIOD_MS) {
                    console.warn(`  ⚠ ${issuerId}/${kid}: deprecated key past 90-day grace period, should be revoked`);
                    warnings++;
                }
            }

            // Deprecated key missing deprecated_at
            if (key.status === 'deprecated' && !key.deprecated_at) {
                console.warn(`  ⚠ ${issuerId}/${kid}: status is 'deprecated' but deprecated_at is not set`);
                warnings++;
            }

            // Revoked key missing revoked_at
            if (key.status === 'revoked' && !key.revoked_at) {
                console.warn(`  ⚠ ${issuerId}/${kid}: status is 'revoked' but revoked_at is not set`);
                warnings++;
            }

            // Active key with revoked_at or deprecated_at set
            if (key.status === 'active' && key.revoked_at) {
                console.warn(`  ⚠ ${issuerId}/${kid}: status is 'active' but revoked_at is set`);
                warnings++;
            }
            if (key.status === 'active' && key.deprecated_at) {
                console.warn(`  ⚠ ${issuerId}/${kid}: status is 'active' but deprecated_at is set`);
                warnings++;
            }

            if (key.status === 'active' && (!key.expires_at || new Date(key.expires_at).getTime() >= now)) {
                activeKeyCount++;
            }
        }

        // Active issuer with no active keys
        if (entry.status === 'active' && activeKeyCount === 0) {
            console.warn(`  ⚠ ${issuerId}: active issuer has no active, non-expired keys`);
            warnings++;
        }
    }

    return warnings;
}

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

        const warningCount = validateEntries(entries);
        if (warningCount > 0) {
            console.warn(`Validation: ${warningCount} warning(s)`);
        }

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
