import * as fs from 'fs';
import * as path from 'path';
import { Octokit } from '@octokit/rest';

// ── Constants ────────────────────────────────────────────────────────────────
const UPSTREAM_OWNER = 'FransDevelopment';
const UPSTREAM_REPO  = 'open-agent-trust-registry';

const ISSUER_ID_PATTERN = /^[a-z0-9][a-z0-9-]*[a-z0-9]$/;

const REQUIRED_ENTRY_FIELDS = [
    'issuer_id', 'display_name', 'website', 'security_contact',
    'status', 'added_at', 'last_verified', 'public_keys', 'capabilities'
] as const;

const FORK_POLL_INTERVAL_MS = 3000;
const FORK_POLL_MAX_ATTEMPTS = 10;

// ── Interface ────────────────────────────────────────────────────────────────
interface SubmitOptions {
    issuerId: string;
    githubToken?: string;
    jsonFile?: string;
    proofFile?: string;
    dryRun?: boolean;
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Sanitise error messages so that tokens/credentials are never printed.
 */
function safeErrorMessage(err: unknown): string {
    if (err instanceof Error) {
        // Octokit errors attach the full request object — strip it
        return err.message.replace(/token\s+\S+/gi, 'token [REDACTED]');
    }
    return String(err);
}

/**
 * Resolve the issuer JSON path from either the explicit flag or the default
 * convention used by `agent-trust register`.
 */
function resolveJsonPath(issuerId: string, explicit?: string): string {
    if (explicit) return path.resolve(process.cwd(), explicit);
    return path.join(process.cwd(), `${issuerId}.json`);
}

/**
 * Resolve the proof file path from either the explicit flag or the two
 * conventional locations used by `agent-trust prove`:
 *   1. ./registry/proofs/<id>.proof  (default output of `prove`)
 *   2. ./<id>.proof                  (fallback / manual placement)
 */
function resolveProofPath(issuerId: string, explicit?: string): string {
    if (explicit) return path.resolve(process.cwd(), explicit);

    const defaultProvePath = path.join(process.cwd(), 'registry', 'proofs', `${issuerId}.proof`);
    if (fs.existsSync(defaultProvePath)) return defaultProvePath;

    return path.join(process.cwd(), `${issuerId}.proof`);
}

// ── Local pre-flight validation ──────────────────────────────────────────────

function validateIssuerId(issuerId: string): void {
    if (!ISSUER_ID_PATTERN.test(issuerId)) {
        console.error(
            `❌ Error: Invalid issuer-id "${issuerId}". ` +
            `Must be lowercase alphanumeric with hyphens, no leading/trailing hyphens.`
        );
        process.exit(1);
    }
}

function validateIssuerJson(raw: string, issuerId: string): Record<string, any> {
    let parsed: Record<string, any>;
    try {
        parsed = JSON.parse(raw);
    } catch {
        console.error('❌ Error: Issuer JSON file contains invalid JSON.');
        process.exit(1);
    }

    const missing = REQUIRED_ENTRY_FIELDS.filter(f => !(f in parsed));
    if (missing.length > 0) {
        console.error(`❌ Error: Issuer JSON is missing required fields: ${missing.join(', ')}`);
        process.exit(1);
    }

    if (parsed.issuer_id !== issuerId) {
        console.error(
            `❌ Error: issuer_id in JSON ("${parsed.issuer_id}") does not match ` +
            `the --issuer-id argument ("${issuerId}").`
        );
        process.exit(1);
    }

    const activeKeys = (parsed.public_keys || []).filter(
        (k: any) => k.status === 'active' && k.algorithm === 'Ed25519'
    );
    if (activeKeys.length === 0) {
        console.error('❌ Error: Issuer JSON must contain at least one active Ed25519 key in public_keys.');
        process.exit(1);
    }

    return parsed;
}

function validateProofFile(content: string, issuerId: string): void {
    if (!content.includes('-----BEGIN OATR KEY OWNERSHIP PROOF-----') ||
        !content.includes('-----END OATR KEY OWNERSHIP PROOF-----')) {
        console.error('❌ Error: Proof file is missing BEGIN/END delimiters.');
        process.exit(1);
    }

    const sigMatch = content.match(/^Signature:\s*(.+?)\s*$/m);
    const msgMatch = content.match(/^Canonical-Message:\s*(.+?)\s*$/m);

    if (!sigMatch) {
        console.error('❌ Error: Proof file is missing the Signature field.');
        process.exit(1);
    }
    if (!msgMatch) {
        console.error('❌ Error: Proof file is missing the Canonical-Message field.');
        process.exit(1);
    }

    const expectedMsg = `oatr-proof-v1:${issuerId}`;
    if (msgMatch[1] !== expectedMsg) {
        console.error(
            `❌ Error: Proof Canonical-Message mismatch. Expected "${expectedMsg}", got "${msgMatch[1]}".`
        );
        process.exit(1);
    }
}

// ── Fork helpers ─────────────────────────────────────────────────────────────

async function ensureFork(octokit: Octokit, forkOwner: string): Promise<void> {
    try {
        await octokit.rest.repos.get({ owner: forkOwner, repo: UPSTREAM_REPO });
        console.log(`   ✅ Found existing fork ${forkOwner}/${UPSTREAM_REPO}`);
    } catch (err: unknown) {
        const status = (err as any)?.status;
        if (status !== 404) {
            console.error(`❌ Error checking for fork: ${safeErrorMessage(err)}`);
            process.exit(1);
        }

        console.log('   🔄 Creating fork...');
        try {
            await octokit.rest.repos.createFork({
                owner: UPSTREAM_OWNER,
                repo: UPSTREAM_REPO
            });
        } catch (forkErr: unknown) {
            console.error(`❌ Failed to create fork: ${safeErrorMessage(forkErr)}`);
            process.exit(1);
        }

        // Poll until the fork is ready
        console.log('   ⏳ Waiting for GitHub to provision fork...');
        for (let i = 0; i < FORK_POLL_MAX_ATTEMPTS; i++) {
            await new Promise(r => setTimeout(r, FORK_POLL_INTERVAL_MS));
            try {
                await octokit.rest.repos.get({ owner: forkOwner, repo: UPSTREAM_REPO });
                console.log('   ✅ Fork is ready');
                return;
            } catch { /* not ready yet */ }
        }

        console.error('❌ Timed out waiting for fork to become available. Please try again in a few minutes.');
        process.exit(1);
    }
}

// ── Main ─────────────────────────────────────────────────────────────────────

export const submit = async (options: SubmitOptions) => {
    const { issuerId } = options;

    // ── 1. Validate issuer-id format ─────────────────────────────────────
    console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('  OATR Registry — Submit Registration');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    validateIssuerId(issuerId);

    // ── 2. Locate and validate local files ───────────────────────────────
    const jsonPath  = resolveJsonPath(issuerId, options.jsonFile);
    const proofPath = resolveProofPath(issuerId, options.proofFile);

    if (!fs.existsSync(jsonPath)) {
        console.error(
            `❌ Error: Issuer entry not found at ${jsonPath}\n` +
            `   Generate one with: npx @open-agent-trust/cli register --issuer-id ${issuerId} ...`
        );
        process.exit(1);
    }

    if (!fs.existsSync(proofPath)) {
        console.error(
            `❌ Error: Proof file not found.\n` +
            `   Searched:\n` +
            `     • ./registry/proofs/${issuerId}.proof\n` +
            `     • ./${issuerId}.proof\n` +
            `   Generate one with: npx @open-agent-trust/cli prove --issuer-id ${issuerId} --private-key <path>`
        );
        process.exit(1);
    }

    const jsonContent  = fs.readFileSync(jsonPath, 'utf8');
    const proofContent = fs.readFileSync(proofPath, 'utf8');

    console.log('[1/5] Validating local files...');
    const issuerData = validateIssuerJson(jsonContent, issuerId);
    validateProofFile(proofContent, issuerId);
    console.log('      ✅ Issuer JSON schema valid');
    console.log('      ✅ Proof file format valid');

    // ── 3. Dry-run gate ──────────────────────────────────────────────────
    if (options.dryRun) {
        console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
        console.log('  🏁 Dry Run Complete — No changes were made');
        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
        console.log(`  Issuer ID:    ${issuerId}`);
        console.log(`  Display Name: ${issuerData.display_name}`);
        console.log(`  Website:      ${issuerData.website}`);
        console.log(`  JSON file:    ${jsonPath}`);
        console.log(`  Proof file:   ${proofPath}`);
        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
        console.log('\n  Remove --dry-run to submit for real.\n');
        return;
    }

    // ── 4. Require token (only for real submissions) ─────────────────────
    const token = options.githubToken || process.env.GITHUB_TOKEN;
    if (!token) {
        console.error(
            '❌ Error: A GitHub personal access token is required.\n' +
            '   Pass --github-token <token> or set the GITHUB_TOKEN environment variable.\n' +
            '   The token needs the "public_repo" scope (or "repo" for private forks).'
        );
        process.exit(1);
    }

    // ── 5. Authenticate ──────────────────────────────────────────────────
    console.log('[2/5] Authenticating with GitHub...');
    const octokit = new Octokit({ auth: token });

    let login: string;
    try {
        const { data } = await octokit.rest.users.getAuthenticated();
        login = data.login;
        console.log(`      ✅ Authenticated as ${login}`);
    } catch (err: unknown) {
        console.error(`❌ GitHub authentication failed: ${safeErrorMessage(err)}`);
        process.exit(1);
    }

    // ── 6. Ensure fork ───────────────────────────────────────────────────
    console.log('[3/5] Ensuring fork exists...');
    await ensureFork(octokit, login);

    // ── 6. Create branch + atomic commit via Git Tree API ────────────────
    console.log('[4/5] Creating branch and committing files...');

    let baseSha: string;
    try {
        const { data: ref } = await octokit.rest.git.getRef({
            owner: UPSTREAM_OWNER,
            repo: UPSTREAM_REPO,
            ref: 'heads/main'
        });
        baseSha = ref.object.sha;
    } catch (err: unknown) {
        console.error(`❌ Failed to fetch upstream main branch: ${safeErrorMessage(err)}`);
        process.exit(1);
    }

    const branchName = `register/${issuerId}`;

    // Check for an existing branch (idempotency for retries)
    let branchExists = false;
    try {
        await octokit.rest.git.getRef({
            owner: login,
            repo: UPSTREAM_REPO,
            ref: `heads/${branchName}`
        });
        branchExists = true;
    } catch { /* branch doesn't exist — expected */ }

    if (branchExists) {
        console.error(
            `❌ Error: Branch "${branchName}" already exists on your fork.\n` +
            `   This likely means a previous submission is still open.\n` +
            `   Check https://github.com/${UPSTREAM_OWNER}/${UPSTREAM_REPO}/pulls for an existing PR.`
        );
        process.exit(1);
    }

    try {
        // Create blobs
        const [jsonBlob, proofBlob] = await Promise.all([
            octokit.rest.git.createBlob({
                owner: login,
                repo: UPSTREAM_REPO,
                content: Buffer.from(jsonContent).toString('base64'),
                encoding: 'base64'
            }),
            octokit.rest.git.createBlob({
                owner: login,
                repo: UPSTREAM_REPO,
                content: Buffer.from(proofContent).toString('base64'),
                encoding: 'base64'
            })
        ]);

        // Create tree
        const { data: tree } = await octokit.rest.git.createTree({
            owner: login,
            repo: UPSTREAM_REPO,
            base_tree: baseSha,
            tree: [
                {
                    path: `registry/issuers/${issuerId}.json`,
                    mode: '100644',
                    type: 'blob',
                    sha: jsonBlob.data.sha
                },
                {
                    path: `registry/proofs/${issuerId}.proof`,
                    mode: '100644',
                    type: 'blob',
                    sha: proofBlob.data.sha
                }
            ]
        });

        // Create commit
        const { data: commit } = await octokit.rest.git.createCommit({
            owner: login,
            repo: UPSTREAM_REPO,
            message: `Register issuer: ${issuerId}\n\nAdds issuer entry and proof-of-key-ownership for automated verification.`,
            tree: tree.sha,
            parents: [baseSha]
        });

        // Create branch reference pointing to the new commit
        await octokit.rest.git.createRef({
            owner: login,
            repo: UPSTREAM_REPO,
            ref: `refs/heads/${branchName}`,
            sha: commit.sha
        });

        console.log(`      ✅ Branch "${branchName}" created with atomic commit`);
    } catch (err: unknown) {
        console.error(`❌ Failed to create branch and commit files: ${safeErrorMessage(err)}`);
        process.exit(1);
    }

    // ── 7. Open Pull Request ─────────────────────────────────────────────
    console.log('[5/5] Opening Pull Request...');

    const prBody = [
        `## Issuer Registration: \`${issuerId}\``,
        '',
        `| Field | Value |`,
        `|-------|-------|`,
        `| **Issuer ID** | \`${issuerId}\` |`,
        `| **Display Name** | ${issuerData.display_name} |`,
        `| **Website** | ${issuerData.website} |`,
        `| **Contact** | ${issuerData.security_contact} |`,
        `| **Algorithm** | Ed25519 |`,
        '',
        '### Files',
        `- \`registry/issuers/${issuerId}.json\` — Issuer entry`,
        `- \`registry/proofs/${issuerId}.proof\` — Proof of key ownership`,
        '',
        '---',
        '',
        '*Submitted via `@open-agent-trust/cli submit`. The CI pipeline will automatically verify ',
        'schema compliance, proof-of-key-ownership, and domain ownership before auto-merging.*'
    ].join('\n');

    try {
        const { data: pr } = await octokit.rest.pulls.create({
            owner: UPSTREAM_OWNER,
            repo: UPSTREAM_REPO,
            title: `Register issuer: ${issuerId}`,
            head: `${login}:${branchName}`,
            base: 'main',
            body: prBody,
            maintainer_can_modify: true
        });

        console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
        console.log('  🎉 Registration Submitted Successfully');
        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
        console.log(`  Issuer ID:  ${issuerId}`);
        console.log(`  PR:         ${pr.html_url}`);
        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
        console.log('\n  The registry CI will now automatically:');
        console.log('    1. Validate your issuer JSON schema');
        console.log('    2. Verify your proof-of-key-ownership');
        console.log('    3. Confirm domain ownership via .well-known/agent.json');
        console.log('    4. Auto-merge if all checks pass ✅\n');
    } catch (err: unknown) {
        // Attempt to clean up the branch on PR creation failure
        try {
            await octokit.rest.git.deleteRef({
                owner: login,
                repo: UPSTREAM_REPO,
                ref: `heads/${branchName}`
            });
        } catch { /* best-effort cleanup */ }

        console.error(`❌ Failed to create Pull Request: ${safeErrorMessage(err)}`);
        process.exit(1);
    }
};
