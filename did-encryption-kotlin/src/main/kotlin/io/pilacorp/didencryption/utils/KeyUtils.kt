package io.pilacorp.didencryption.utils

import io.pilacorp.didencryption.curve.Secp256k1
import org.bouncycastle.crypto.generators.ECKeyPairGenerator
import org.bouncycastle.crypto.params.ECKeyGenerationParameters
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.math.ec.ECPoint
import java.math.BigInteger
import java.security.SecureRandom

/**
 * Holds a secp256k1 key pair.
 * The private key is a scalar BigInteger (the "d" value).
 * The public key is a point on the curve: G * d.
 */
data class KeyPair(val privateKey: BigInteger, val publicKey: ECPoint)

/**
 * Generate a fresh secp256k1 key pair using a secure random source.
 * Go: func GenerateKeys() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error)
 */
fun generateKeys(): KeyPair {
    val generator = ECKeyPairGenerator()
    generator.init(ECKeyGenerationParameters(Secp256k1.domainParams, SecureRandom()))
    val pair = generator.generateKeyPair()
    val d = (pair.private as ECPrivateKeyParameters).d
    val q = (pair.public as ECPublicKeyParameters).q.normalize()
    return KeyPair(d, q)
}

/**
 * Parse a hex-encoded private key scalar (with or without "0x" prefix).
 * Go: func PrivateKeyStrToKey(hexKey string) (*ecdsa.PrivateKey, error)
 */
fun privateKeyStrToKey(hexKey: String): BigInteger =
    BigInteger(hexKey.removePrefix("0x"), 16)

/**
 * Serialize a private key scalar to a 32-byte zero-padded big-endian hex string.
 * Matches go-ethereum's hex.EncodeToString(crypto.FromECDSA(priv)).
 * Go: func PrivateKeyToHexString(priv *ecdsa.PrivateKey) string
 */
fun privateKeyToHexString(priv: BigInteger): String {
    val raw = priv.toByteArray()
    val out = ByteArray(32)
    when {
        // BigInteger.toByteArray() adds a leading 0x00 sign byte when the MSB is set
        raw.size == 33 && raw[0] == 0.toByte() -> raw.copyInto(out, destinationOffset = 0, startIndex = 1)
        raw.size <= 32 -> raw.copyInto(out, destinationOffset = 32 - raw.size)
        else -> raw.copyInto(out, destinationOffset = 0, startIndex = raw.size - 32)
    }
    return out.toHexString()
}

/**
 * Serialize a public key to a 33-byte compressed hex string (02/03 || X).
 * Matches go-ethereum's hex.EncodeToString(crypto.CompressPubkey(pub)).
 * Go: func PublicKeyToCompressedKey(pub *ecdsa.PublicKey) string
 */
fun publicKeyToCompressedKey(pub: ECPoint): String =
    pub.normalize().getEncoded(true).toHexString()  // true = compressed → 33 bytes

/**
 * Parse a compressed (33-byte) hex public key back to an ECPoint.
 * Go: func PublicCompressedKeyToKey(hexPub string) (*ecdsa.PublicKey, error)
 */
fun publicCompressedKeyToKey(hexPub: String): ECPoint =
    Secp256k1.decodePoint(hexPub.removePrefix("0x").hexToByteArray())

// ---------------------------------------------------------------------------
// Hex encoding helpers (internal use across the package)
// ---------------------------------------------------------------------------

internal fun ByteArray.toHexString(): String =
    joinToString("") { "%02x".format(it) }

internal fun String.hexToByteArray(): ByteArray {
    require(length % 2 == 0) { "Hex string length must be even, got $length" }
    return ByteArray(length / 2) { i ->
        ((Character.digit(this[2 * i], 16) shl 4) or
                Character.digit(this[2 * i + 1], 16)).toByte()
    }
}
