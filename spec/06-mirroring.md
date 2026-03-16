# 06 - Mirroring Protocol

The Open Agent Trust Registry architecture relies heavily on distribution. Anyone can run an exact mirror of the complete registry manifest. 

By pulling and serving a signed registry, mirrors offload verification network requests from the central reference server onto fully decentralized infrastructure.

## Hosting a Regional Mirror

1. **Fetch:** Perform an initial clone or HTTP fetch of the complete signed registry JSON manifest (`manifest.json`) from any active mirror or directly from the primary reference server.
2. **Verify Offline:** Mathematically verify the registry `signature` algorithm against the well-known public root keys belonging to the Governance Council.
3. **Serve:** Expose the verified JSON state at your own URL endpoint.
4. **Resynchronize:** Configure a CRON or automated task to re-fetch the upstream manifest files periodically. (Recommended minimum frequency: Every 15 minutes. Mandated required frequency: At least every 24 hours).

## Mirror Requirements
To ensure relying services do not accept stale data that may disguise a critical runtime compromise:
- Mirrors MUST serve the `generated_at` timestamp exactingly.
- Clients MUST automatically REJECT manifests possessing an `expires_at` timestamp placed strictly in the past. 
- Mirrors MUST serve the time-critical `revocations.json` alongside the primary registry `manifest.json`.
- Mirrors MUST NOT under any circumstances modify registry content prior to serving it (doing so instantly invalidates the structural root signature verification for end clients).
- Mirrors SHOULD serve the files globally via modern, high-bandwidth HTTPS/TLS edge networks.
