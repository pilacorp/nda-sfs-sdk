package io.pilacorp.didencryption.didencrypt

import io.pilacorp.didencryption.curve.*
import io.pilacorp.didencryption.utils.*
import org.bouncycastle.math.ec.ECPoint
import java.math.BigInteger

// ---------------------------------------------------------------------------
// Internal PRE (Proxy Re-Encryption) core functions
// ---------------------------------------------------------------------------

/**
 * Generate an AES symmetric key from a public key by creating a fresh capsule.
 *
 * Returns (capsule, 32-byte keyBytes) where keyBytes = SHA3-256(G*(priE+priV)*pubKey).
 *
 * Go: func generateAESKey(pubKey *ecdsa.PublicKey, chunkSize uint32) (cap *capsule, keyBytes []byte, err error)
 */
internal fun generateAESKey(pubKey: ECPoint, chunkSize: Int): Pair<Capsule, ByteArray> {
    val (priEd, pubE) = generateKeys()
    val (priVd, pubV) = generateKeys()

    val h = hashToCurve(concatBytes(pointToBytes(pubE), pointToBytes(pubV)))

    // s = priV + priE * h  (mod N)
    val s = bigIntAdd(priVd, bigIntMul(priEd, h))

    // point = pubKey * (priE + priV)
    val point = pointScalarMul(pubKey, bigIntAdd(priEd, priVd))

    val keyBytes = sha3Hash(pointToBytes(point))

    val cap = Capsule(e = pubE, v = pubV, s = s, chunkSize = chunkSize)
    return Pair(cap, keyBytes)
}

/**
 * Decrypt the AES key for the *owner* who holds the original private key.
 *
 * Go: func decryptAESKeyByOwner(prvKey *ecdsa.PrivateKey, cap *capsule) ([]byte, error)
 */
internal fun decryptAESKeyByOwner(prvKeyD: BigInteger, cap: Capsule): ByteArray {
    val point = pointScalarMul(pointScalarAdd(cap.e, cap.v), prvKeyD)
    return sha3Hash(pointToBytes(point))
}

/**
 * Decrypt the AES key for a *delegatee* using the re-encrypted capsule and their private key.
 *
 * Go: func decryptAESKey(prvKey *ecdsa.PrivateKey, cap *capsule, pointX *ecdsa.PublicKey) (keyBytes []byte, err error)
 */
internal fun decryptAESKey(prvKeyD: BigInteger, cap: Capsule, pubX: ECPoint): ByteArray {
    val pubKeyPoint = bigIntMulBase(prvKeyD) // public key = G * d

    val s = pointScalarMul(pubX, prvKeyD)

    val d = hashToCurve(
        concatBytes(
            concatBytes(pointToBytes(pubX), pointToBytes(pubKeyPoint)),
            pointToBytes(s)
        )
    )

    val point = pointScalarMul(pointScalarAdd(cap.e, cap.v), d)
    return sha3Hash(pointToBytes(point))
}

/**
 * Generate a re-encryption key (rk) from the owner to a delegatee.
 *
 * Returns (rk, ephemeral-public-key X).
 *
 * Go: func rekeyGenerate(ownerPrvKey *ecdsa.PrivateKey, recieverPubKey *ecdsa.PublicKey)
 */
internal fun rekeyGenerate(ownerPrvKeyD: BigInteger, receiverPubKey: ECPoint): Pair<BigInteger, ECPoint> {
    val (priXd, pubX) = generateKeys()

    val pointS = pointScalarMul(receiverPubKey, priXd)

    val d = hashToCurve(
        concatBytes(
            concatBytes(pointToBytes(pubX), pointToBytes(receiverPubKey)),
            pointToBytes(pointS)
        )
    )

    // rk = ownerD * d^(-1)  (mod N)
    val rk = bigIntMul(ownerPrvKeyD, getInvert(d))

    return Pair(rk, pubX)
}

/**
 * Re-encrypt a capsule with the re-encryption key.
 *
 * Go: func reEncryption(rk *big.Int, cap *capsule) (*capsule, error)
 */
internal fun reEncryption(rk: BigInteger, cap: Capsule): Capsule {
    // Verify capsule integrity: G*S == V + E*H(E||V)
    val lhs = bigIntMulBase(cap.s)
    val h = hashToCurve(concatBytes(pointToBytes(cap.e), pointToBytes(cap.v)))
    val rhs = pointScalarAdd(cap.v, pointScalarMul(cap.e, h))

    check(
        lhs.affineXCoord.toBigInteger() == rhs.affineXCoord.toBigInteger() &&
        lhs.affineYCoord.toBigInteger() == rhs.affineYCoord.toBigInteger()
    ) { "Capsule not match" }

    return Capsule(
        e = pointScalarMul(cap.e, rk),
        v = pointScalarMul(cap.v, rk),
        s = cap.s,
        chunkSize = cap.chunkSize,
        version = cap.version
    )
}

// ---------------------------------------------------------------------------
// Low-level encode/decode helpers kept for parity with Go (internal use)
// ---------------------------------------------------------------------------

/**
 * Go: func createRekey(ownerPrvKey *ecdsa.PrivateKey, recieverPubKey *ecdsa.PublicKey) ([]byte, error)
 */
internal fun createRekey(ownerPrvKeyD: BigInteger, receiverPubKey: ECPoint): ByteArray {
    val (r, p) = rekeyGenerate(ownerPrvKeyD, receiverPubKey)
    return encodeRekey(r, p)
}

/**
 * Go: func reEncrypt(cap []byte, rekeyBytes []byte) ([]byte, error)
 */
internal fun reEncrypt(capBytes: ByteArray, rekeyBytes: ByteArray): ByteArray {
    val (r, pubX) = decodeRekey(rekeyBytes)
    val cap = decodeCapsule(capBytes)
    val reCap = reEncryption(r, cap)
    val reCapBytes = encodeCapsule(reCap)
    return concatBytes(reCapBytes, pointToBytes(pubX))
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Create a re-capsule for [receiverPubKey] from an existing owner [capsule].
 * The result is a 250-byte blob: 185 bytes of re-encrypted capsule + 65 bytes of ephemeral point.
 *
 * Go: func CreateReCapsule(ownerPrvKey, recieverPubKey string, capsule []byte) ([]byte, error)
 */
fun createReCapsule(ownerPrvKey: String, receiverPubKey: String, capsule: ByteArray): ByteArray {
    val ownerD = privateKeyStrToKey(ownerPrvKey)
    val receiverPub = publicCompressedKeyToKey(receiverPubKey)

    val (r, p) = rekeyGenerate(ownerD, receiverPub)

    val cap = decodeCapsule(capsule)
    val reCap = reEncryption(r, cap)
    val reCapBytes = encodeCapsule(reCap)

    return concatBytes(reCapBytes, pointToBytes(p))
}
