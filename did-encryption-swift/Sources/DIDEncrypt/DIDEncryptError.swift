import Foundation

public enum DIDEncryptError: Error, Equatable {
    case invalidHex
    case invalidLength(expected: Int, actual: Int)
    case invalidPrivateKey
    case invalidPublicKey
    case invalidCapsule
    case invalidReCapsule
    case chunkSizeNotSet
    case streamModeNotAllowed
    case invalidCiphertext
    case capsuleMismatch
    case truncatedStream
}

