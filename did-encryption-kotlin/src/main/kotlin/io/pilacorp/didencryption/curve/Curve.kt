package io.pilacorp.didencryption.curve

import org.bouncycastle.crypto.ec.CustomNamedCurves
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.math.ec.ECPoint
import java.math.BigInteger

/**
 * Secp256k1 curve singleton — mirrors the `var CURVE = crypt.S256()` globals in the Go package.
 *
 * Go equivalents:
 *   var CURVE = crypt.S256()
 *   var P     = CURVE.Params().P
 *   var N     = CURVE.Params().N
 */
object Secp256k1 {
    private val x9params = CustomNamedCurves.getByName("secp256k1")

    /** Full EC domain parameters (curve, G, n, h). */
    val domainParams: ECDomainParameters = ECDomainParameters(
        x9params.curve, x9params.g, x9params.n, x9params.h
    )

    /** Generator point G. */
    val G: ECPoint = x9params.g

    /** Field prime P (characteristic of the field). */
    val P: BigInteger = x9params.curve.field.characteristic

    /** Curve order N. */
    val N: BigInteger = x9params.n

    /** Decode an ECPoint from its encoded bytes (compressed or uncompressed). */
    fun decodePoint(bytes: ByteArray): ECPoint =
        x9params.curve.decodePoint(bytes).normalize()

    /** Create a curve point from its (x, y) affine coordinates. */
    fun createPoint(x: BigInteger, y: BigInteger): ECPoint =
        x9params.curve.createPoint(x, y).normalize()
}

// ---------------------------------------------------------------------------
// Point arithmetic (mirrors curve/point.go)
// ---------------------------------------------------------------------------

/**
 * Point addition on the secp256k1 curve.
 * Go: func PointScalarAdd(a, b *CurvePoint) *CurvePoint
 */
fun pointScalarAdd(a: ECPoint, b: ECPoint): ECPoint =
    a.add(b).normalize()

/**
 * Scalar multiplication: returns a * k.
 * Go: func PointScalarMul(a *CurvePoint, k *big.Int) *CurvePoint
 */
fun pointScalarMul(a: ECPoint, k: BigInteger): ECPoint =
    a.multiply(k).normalize()

/**
 * Scalar multiplication with the generator: returns G * k.
 * Go: func BigIntMulBase(k *big.Int) *CurvePoint
 */
fun bigIntMulBase(k: BigInteger): ECPoint =
    Secp256k1.G.multiply(k).normalize()

/**
 * Serialize a point to its 65-byte uncompressed form (0x04 || X || Y).
 * Matches go-ethereum's crypto.FromECDSAPub which calls elliptic.Marshal.
 * Go: func PointToBytes(point *ecdsa.PublicKey) []byte
 */
fun pointToBytes(point: ECPoint): ByteArray =
    point.normalize().getEncoded(false) // false = uncompressed → 65 bytes

/**
 * Deserialize a point from its encoded bytes (accepts both compressed 33-byte
 * and uncompressed 65-byte forms).
 * Go: func BytesToPublicKey(bytes []byte) (*ecdsa.PublicKey, error)
 */
fun bytesToPublicKey(bytes: ByteArray): ECPoint =
    Secp256k1.decodePoint(bytes)
