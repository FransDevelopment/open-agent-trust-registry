import { readFile, writeFile, mkdir } from 'fs/promises';
import { resolve, join, dirname } from 'path';
import * as ed from '@noble/ed25519';

const PROOF_VERSION = 'oatr-proof-v1';
const ISSUER_ID_PATTERN = /^[a-z0-9][a-z0-9-]*[a-z0-9]$/;

export const prove = async (options: {
    issuerId: string;
    privateKey: string;
    outFile?: string;
}) => {
    try {
        // Validate issuer_id format
        if (!ISSUER_ID_PATTERN.test(options.issuerId)) {
            throw new Error(
                `Invalid issuer_id "${options.issuerId}". Must be lowercase alphanumeric and hyphens only, ` +
                `no leading/trailing hyphens. Example: my-runtime`
            );
        }

        console.log('[1/3] Loading Ed25519 private key...');
        const keyPath = resolve(process.cwd(), options.privateKey);
        const privateKeyB64 = await readFile(keyPath, 'utf-8');
        const privateKeyBuffer = Buffer.from(privateKeyB64.trim(), 'base64url');

        if (privateKeyBuffer.length !== 32) {
            throw new Error(
                `Invalid private key length (${privateKeyBuffer.length} bytes). ` +
                `Must be 32 bytes (base64url encoded). Ensure this is an Ed25519 seed from 'agent-trust keygen'.`
            );
        }

        console.log('[2/3] Signing proof-of-key-ownership...');
        const canonicalMessage = `${PROOF_VERSION}:${options.issuerId}`;
        const messageBytes = Buffer.from(canonicalMessage, 'utf8');
        const signatureBytes = await ed.signAsync(messageBytes, privateKeyBuffer);
        const signature = Buffer.from(signatureBytes).toString('base64url');

        const proofContent = [
            '-----BEGIN OATR KEY OWNERSHIP PROOF-----',
            `Canonical-Message: ${canonicalMessage}`,
            `Signature: ${signature}`,
            '-----END OATR KEY OWNERSHIP PROOF-----',
            '' // trailing newline for POSIX compliance
        ].join('\n');

        console.log('[3/3] Writing proof file...');
        const outPath = options.outFile
            ? resolve(process.cwd(), options.outFile)
            : join(process.cwd(), 'registry', 'proofs', `${options.issuerId}.proof`);

        await mkdir(dirname(outPath), { recursive: true });
        await writeFile(outPath, proofContent);

        console.log(`\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
        console.log(`  ✅ Proof of Key Ownership Generated`);
        console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
        console.log(`  Issuer ID:  ${options.issuerId}`);
        console.log(`  Proof file: ${outPath}`);
        console.log(`  Format:     ${PROOF_VERSION}`);
        console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`);

        console.log(`Next steps:\n`);
        console.log(`  1. Ensure your issuer JSON is at registry/issuers/${options.issuerId}.json`);
        console.log(`  2. Ensure your domain verification is live at:`);
        console.log(`     https://yourdomain.com/.well-known/agent-trust.json\n`);
        console.log(`  3. Submit a Pull Request with both files:`);
        console.log(`     - registry/issuers/${options.issuerId}.json`);
        console.log(`     - registry/proofs/${options.issuerId}.proof\n`);
        console.log(`  The CI pipeline will verify your proof, check your domain,`);
        console.log(`  and auto-merge if all checks pass.\n`);

    } catch (error: any) {
        console.error('❌ Failed to generate proof:', error.message);
        process.exit(1);
    }
};
