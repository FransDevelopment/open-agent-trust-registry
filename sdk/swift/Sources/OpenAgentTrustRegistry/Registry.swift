import Foundation

public class OpenAgentTrustRegistryClient {
    private let mirrorUrl: URL
    private var manifest: RegistryManifest?
    private var revocations: RevocationList?
    private var lastFetchTime: Date?
    
    // Refresh cache every 15 minutes by default
    private let cacheTTL: TimeInterval = 15 * 60

    private init(mirrorUrl: URL) {
        self.mirrorUrl = mirrorUrl
    }

    /// Initialize a new Registry Client and aggressively fetch the initial state.
    public static func load(mirrorUrl: URL) async throws -> OpenAgentTrustRegistryClient {
        let registry = OpenAgentTrustRegistryClient(mirrorUrl: mirrorUrl)
        try await registry.refresh()
        return registry
    }

    /// Manually trigger a refresh of the cached registry state from the network.
    public func refresh() async throws {
        // Build the precise endpoint URLs
        let manifestUrl = mirrorUrl.appendingPathComponent("v1/registry")
        let revocationsUrl = mirrorUrl.appendingPathComponent("v1/revocations")
        
        async let manifestTask = URLSession.shared.data(from: manifestUrl)
        async let revocationsTask = URLSession.shared.data(from: revocationsUrl)
        
        let (manifestData, manifestResponse) = try await manifestTask
        let (revocationsData, revocationsResponse) = try await revocationsTask
        
        guard let httpManifest = manifestResponse as? HTTPURLResponse, httpManifest.statusCode == 200,
              let httpRevocations = revocationsResponse as? HTTPURLResponse, httpRevocations.statusCode == 200 else {
            throw OpenAgentTrustRegistryError.fetchFailed("Failed to fetch remote registry state (non-200 HTTP response).")
        }
        
        let decoder = JSONDecoder()
        manifest = try decoder.decode(RegistryManifest.self, from: manifestData)
        revocations = try decoder.decode(RevocationList.self, from: revocationsData)
        lastFetchTime = Date()
    }
    
    /// Verify an incoming agent attestation locally against the cached registry JSON.
    public func verify(attestationJws: String, expectedAudience: String, expectedNonce: String? = nil) async throws -> VerificationResult {
        
        // Auto-refresh the cache if it's considered stale
        if let lastFetch = lastFetchTime, Date().timeIntervalSince(lastFetch) > cacheTTL {
            try await refresh()
        }
        
        guard let manifest = manifest, let revocations = revocations else {
            throw OpenAgentTrustRegistryError.registryNotLoaded
        }
        
        return Verification.verifyAttestation(
            attestationJws: attestationJws,
            manifest: manifest,
            revocations: revocations,
            expectedAudience: expectedAudience,
            expectedNonce: expectedNonce
        )
    }
}
