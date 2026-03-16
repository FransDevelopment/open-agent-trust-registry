import { OpenAgentTrustRegistry } from '@open-agent-trust/registry';

export const verify = async (attestation: string, options: { audience: string; mirror: string }) => {
    try {
        console.log(`[1/2] Fetching registry manifest from mirror (${options.mirror})...`);
        const registry = await OpenAgentTrustRegistry.load(options.mirror);
        
        console.log(`[2/2] Attempting 14-step verification against audience bounds (${options.audience})...`);
        const result = await registry.verifyToken(attestation, options.audience);

        if (result.valid) {
            console.log(`\n✅ Valid Attestation`);
            console.log(`Issuer:         ${result.issuer?.display_name} (${result.issuer?.issuer_id})`);
            console.log(`Token Subject:  ${result.claims?.sub}`);
            console.log(`Authorized As:  ${result.claims?.user_pseudonym}`);
            console.log(`Expires:        ${new Date(result.claims?.exp! * 1000).toISOString()}`);
            console.log(`Constraints:    `, result.claims?.constraints);
            process.exit(0);
        } else {
            console.error(`\n❌ Token mathematically rejected by the Registry.`);
            console.error(`Reason: ${result.reason}`);
            
            if (result.issuer) {
                console.error(`Identified Issuer: ${result.issuer.display_name}`);
            }
            process.exit(1);
        }
    } catch (err: any) {
        console.error(`\n❌ Verification engine failure: ${err.message}`);
        process.exit(1);
    }
};
