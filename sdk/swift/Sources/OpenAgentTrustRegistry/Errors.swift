import Foundation

public enum OpenAgentTrustRegistryError: Error, LocalizedError {
    case fetchFailed(String)
    case invalidRegistrySignature(String)
    case staleRegistryState(String)
    case malformedRegistryState(String)
    case unknownRootKey(String)
    case registryNotLoaded

    public var errorDescription: String? {
        switch self {
        case .fetchFailed(let message),
             .invalidRegistrySignature(let message),
             .staleRegistryState(let message),
             .malformedRegistryState(let message),
             .unknownRootKey(let message):
            return message
        case .registryNotLoaded:
            return "Registry state not loaded."
        }
    }
}
