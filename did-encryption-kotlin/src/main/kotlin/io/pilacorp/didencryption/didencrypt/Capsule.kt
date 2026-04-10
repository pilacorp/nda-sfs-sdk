package io.pilacorp.didencryption.didencrypt

import io.pilacorp.didencryption.curve.Secp256k1
import org.bouncycastle.math.ec.ECPoint
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * PRE capsule — holds the material needed to derive the AES key.
 *
 * Serialized layout (185 bytes, all length prefixes are uint32 LE):
 *   [4 | len(E.X)] [E.X bytes]
 *   [4 | len(E.Y)] [E.Y bytes]
 *   [4 | len(V.X)] [V.X bytes]
 *   [4 | len(V.Y)] [V.Y bytes]
 *   [4 | len(S)  ] [S bytes  ]
 *   [4 | chunkSize (uint32 LE)]
 *   [1 | version (uint8)     ]
 *
 * Maximum: 5 × (4 + 32) + 4 + 1 = 185 bytes.
 *
 * Go: type capsule struct { E, V *ecdsa.PublicKey; S *big.Int; ChunkSize uint32; Version uint8 }
 */
internal data class Capsule(
    val e: ECPoint,
    val v: ECPoint,
    val s: BigInteger,
    val chunkSize: Int,   // uint32 in Go; practical values are small (0 or chunk size in bytes)
    val version: Byte = 0
)

// ---------------------------------------------------------------------------
// Serialization helpers
// ---------------------------------------------------------------------------

/**
 * Serialize a capsule to bytes.
 * Go: func encodeCapsule(cap *capsule) ([]byte, error)
 */
internal fun encodeCapsule(cap: Capsule): ByteArray {
    val buf = mutableListOf<Byte>()

    fun writeBigInt(value: BigInteger) {
        // secp256k1 field elements and scalars are always <= 32 bytes.
        // Zero-pad to exactly 32 bytes so the capsule is always a fixed 185 bytes,
        // matching Go's assumption that coordinates are full 32-byte values.
        val raw = value.toByteArray()
        val stripped = if (raw.size > 1 && raw[0] == 0.toByte()) raw.copyOfRange(1, raw.size) else raw
        val padded = ByteArray(32).also { stripped.copyInto(it, 32 - stripped.size) }

        // Length prefix as uint32 LE (always 32)
        val lenBuf = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(32).array()
        buf.addAll(lenBuf.toList())
        buf.addAll(padded.toList())
    }

    val en = cap.e.normalize()
    val vn = cap.v.normalize()

    writeBigInt(en.affineXCoord.toBigInteger())
    writeBigInt(en.affineYCoord.toBigInteger())
    writeBigInt(vn.affineXCoord.toBigInteger())
    writeBigInt(vn.affineYCoord.toBigInteger())
    writeBigInt(cap.s)

    // ChunkSize as uint32 LE
    val csBytes = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(cap.chunkSize).array()
    buf.addAll(csBytes.toList())

    // Version as uint8
    buf.add(cap.version)

    return buf.toByteArray()
}

/**
 * Deserialize a capsule from bytes.
 * Go: func decodeCapsule(data []byte) (*capsule, error)
 */
internal fun decodeCapsule(data: ByteArray): Capsule {
    val buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)

    fun readBigInt(): BigInteger {
        val len = buf.int                       // uint32 LE → Java signed int (safe for ≤2 GB)
        check(len >= 0) { "Negative length in capsule data" }
        val bytes = ByteArray(len).also { buf.get(it) }
        return BigInteger(1, bytes)             // positive, big-endian
    }

    val eX = readBigInt()
    val eY = readBigInt()
    val vX = readBigInt()
    val vY = readBigInt()
    val s  = readBigInt()

    val chunkSize = buf.int                     // uint32 LE
    val version   = buf.get()                  // uint8

    val ePoint = Secp256k1.createPoint(eX, eY)
    val vPoint = Secp256k1.createPoint(vX, vY)

    return Capsule(ePoint, vPoint, s, chunkSize, version)
}

// ---------------------------------------------------------------------------
// Rekey helpers (encodeRekey / decodeRekey) — kept for completeness
// ---------------------------------------------------------------------------

/**
 * Go: func encodeRekey(r *big.Int, p *ecdsa.PublicKey) ([]byte, error)
 */
internal fun encodeRekey(r: BigInteger, p: ECPoint): ByteArray {
    val buf = mutableListOf<Byte>()

    fun writeBigInt(value: BigInteger) {
        val raw = value.toByteArray()
        val stripped = if (raw.size > 1 && raw[0] == 0.toByte()) raw.copyOfRange(1, raw.size) else raw
        val padded = ByteArray(32).also { stripped.copyInto(it, 32 - stripped.size) }
        val lenBuf = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(32).array()
        buf.addAll(lenBuf.toList())
        buf.addAll(padded.toList())
    }

    writeBigInt(r)
    val pn = p.normalize()
    writeBigInt(pn.affineXCoord.toBigInteger())
    writeBigInt(pn.affineYCoord.toBigInteger())

    return buf.toByteArray()
}

/**
 * Go: func decodeRekey(data []byte) (*big.Int, *ecdsa.PublicKey, error)
 */
internal fun decodeRekey(data: ByteArray): Pair<BigInteger, ECPoint> {
    val buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)

    fun readBigInt(): BigInteger {
        val len = buf.int
        check(len >= 0) { "Negative length in rekey data" }
        val bytes = ByteArray(len).also { buf.get(it) }
        return BigInteger(1, bytes)
    }

    val r  = readBigInt()
    val pX = readBigInt()
    val pY = readBigInt()

    return Pair(r, Secp256k1.createPoint(pX, pY))
}
