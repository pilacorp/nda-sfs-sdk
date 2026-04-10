package io.pilacorp.didencryption.utils

import io.pilacorp.didencryption.curve.Secp256k1
import org.bouncycastle.crypto.digests.SHA3Digest
import java.math.BigInteger

/**
 * Hash a message with SHA3-256 (FIPS 202 / NIST standard).
 *
 * Go uses golang.org/x/crypto/sha3's sha3.New256() which is the NIST standard
 * SHA3-256 (not Ethereum's legacy Keccak-256).  Bouncy Castle's SHA3Digest(256)
 * is the equivalent.
 *
 * Go: func Sha3Hash(message []byte) ([]byte, error)
 */
fun sha3Hash(message: ByteArray): ByteArray {
    val digest = SHA3Digest(256)
    digest.update(message, 0, message.size)
    val result = ByteArray(32)
    digest.doFinal(result, 0)
    return result
}

/**
 * Concatenate two byte slices.
 * Go: func ConcatBytes(a, b []byte) []byte
 */
fun concatBytes(a: ByteArray, b: ByteArray): ByteArray = a + b

/**
 * Map a 32-byte hash to a scalar in [0, N) by interpreting the bytes as a
 * big-endian unsigned integer and reducing mod N.
 * Go: func HashToCurve(hash []byte) *big.Int
 */
fun hashToCurve(hash: ByteArray): BigInteger {
    val hashInt = BigInteger(1, hash) // "1" sign = treat bytes as positive (unsigned)
    return hashInt.mod(Secp256k1.N)
}
