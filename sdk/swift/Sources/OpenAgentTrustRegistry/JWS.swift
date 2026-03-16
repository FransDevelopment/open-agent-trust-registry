import Foundation
import Crypto

public enum JWSError: Error {
    case invalidFormat
    case invalidHeader
    case invalidSignature
    case unsupportedAlgorithm
}

public struct JWSHeader: Codable {
    public let alg: String
    public let kid: String?
    public let iss: String?
    public let typ: String?
}

/// A lightweight JWS decoder and verifier built directly on swift-crypto 
/// to avoid bloating the SDK with massive third-party JWT libraries.
public struct JWS {
    
    // Base64URL decoding helper since Foundation only provides standard Base64
    public static func base64URLEncode(_ data: Data) -> String {
        return data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    public static func base64URLDecode(_ string: String) -> Data? {
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        
        // Pad with equals signs to make the string length a multiple of 4
        let paddingLength = 4 - (base64.count % 4)
        if paddingLength < 4 {
            base64 += String(repeating: "=", count: paddingLength)
        }
        
        return Data(base64Encoded: base64)
    }

    /// Extends the raw components of the JWS token. Does NOT cryptographically verify it.
    public static func decode(token: String) throws -> (header: JWSHeader, payloadData: Data, signature: Data, signingInput: String) {
        let parts = token.components(separatedBy: ".")
        guard parts.count == 3 else {
            throw JWSError.invalidFormat
        }

        let headerString = parts[0]
        let payloadString = parts[1]
        let signatureString = parts[2]

        guard let headerData = base64URLDecode(headerString),
              let payloadData = base64URLDecode(payloadString),
              let signatureData = base64URLDecode(signatureString) else {
            throw JWSError.invalidFormat
        }

        let header = try JSONDecoder().decode(JWSHeader.self, from: headerData)
        let signingInput = "\(headerString).\(payloadString)"

        return (header, payloadData, signatureData, signingInput)
    }

    /// Mathematically verifies an EdDSA JWS token against a known Curve25519 (Ed25519) Public Key.
    public static func verifyEdDSA(token: String, publicKeyBase64URL: String) throws -> (header: JWSHeader, payload: Data) {
        let decoded = try decode(token: token)
        
        guard decoded.header.alg == "EdDSA" else {
            throw JWSError.unsupportedAlgorithm
        }
        
        guard let keyData = base64URLDecode(publicKeyBase64URL) else {
            throw JWSError.invalidFormat
        }
        
        let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: keyData)
        
        guard let signingInputData = decoded.signingInput.data(using: .ascii) else {
            throw JWSError.invalidFormat
        }
        
        let isValid = publicKey.isValidSignature(decoded.signature, for: signingInputData)
        
        if isValid {
            return (decoded.header, decoded.payloadData)
        } else {
            throw JWSError.invalidSignature
        }
    }
}
