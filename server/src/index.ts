import { Hono } from 'hono';
import { serve } from '@hono/node-server';
import { readFile } from 'fs/promises';
import { join } from 'path';
import { verifyAttestation, OpenAgentTrustRegistry } from '@open-agent-trust/registry';

const app = new Hono();

// Configurable via environment variable for deployment; defaults to local dev path
const REGISTRY_DIR = process.env.REGISTRY_PATH || join(process.cwd(), '../registry');

// 1. GET /v1/registry (Serve the full manifest)
app.get('/v1/registry', async (c) => {
    try {
        const manifestStr = await readFile(join(REGISTRY_DIR, 'manifest.json'), 'utf8');
        const manifest = JSON.parse(manifestStr);
        return c.json(manifest);
    } catch (e) {
        return c.json({ error: 'Registry manifest unavailable' }, 500);
    }
});

// 2. GET /v1/registry/:issuer_id
app.get('/v1/registry/:issuer_id', async (c) => {
    const issuerId = c.req.param('issuer_id');
    try {
        // Technically this could just be read from the manifest to save disk IO,
        // but it mimics reading the raw registration file perfectly.
        const fileStr = await readFile(join(REGISTRY_DIR, `issuers/${issuerId}.json`), 'utf8');
        return c.json(JSON.parse(fileStr));
    } catch (e) {
        return c.json({ error: 'Issuer not found' }, 404);
    }
});

// 3. GET /v1/revocations
app.get('/v1/revocations', async (c) => {
    try {
         const fileStr = await readFile(join(REGISTRY_DIR, 'revocations.json'), 'utf8');
         return c.json(JSON.parse(fileStr));
    } catch (e) {
         return c.json({ error: 'Revocations unavailable' }, 500);
    }
});

// 4. POST /v1/verify
// A convenience wrapper for lightweight clients utilizing our robust TS SDK
app.post('/v1/verify', async (c) => {
    try {
        const body = await c.req.json();
        
        if (!body.attestation || !body.audience) {
            return c.json({ error: 'Missing required attestation or audience fields' }, 400);
        }

        // Technically, a stateless server shouldn't cache the local files using standard fetch
        // within the registry agent, but for a simple wrapper we read the states fresh
        const manifestStr = await readFile(join(REGISTRY_DIR, 'manifest.json'), 'utf8');
        const revocationsStr = await readFile(join(REGISTRY_DIR, 'revocations.json'), 'utf8');

        // Fire the agnostic 14-step SDK engine
        const result = await verifyAttestation(
            body.attestation,
            JSON.parse(manifestStr),
            JSON.parse(revocationsStr),
            body.audience,
            body.nonce
        );

        return c.json(result);
    } catch (e) {
        return c.json({ error: 'Invalid verification payload' }, 400);
    }
});

// 5. POST /v1/register (Stub for PR generation via GitHub API/Actions)
app.post('/v1/register', async (c) => {
    return c.json({ 
        message: 'Registration via API is not currently active.// The server serves files; it doesn\'t need to load the registry via OpenAgentTrustRegistry repository.' 
    }, 405);
});

// Health check
app.get('/health', (c) => c.json({ status: 'ok', time: new Date().toISOString() }));

const port = 3000;
console.log(`Open Agent Trust Registry running at http://localhost:${port}`);

serve({
  fetch: app.fetch,
  port
});
