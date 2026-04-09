package io.pilacorp.didencryption.didencrypt

import io.pilacorp.didencryption.utils.publicCompressedKeyToKey
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Holds the derived AES key and base nonce used for encryption.
 *
 * Construct via [Encryptor.create].
 *
 * When [chunkSize] == 0  → use [encrypt]  (single-shot, non-stream mode).
 * When [chunkSize] >  0  → use [encryptStream] (streaming mode).
 *
 * Go: type Encryptor struct { aesKey [32]byte; baseNonce [12]byte; chunkSize uint32 }
 */
class Encryptor internal constructor(
    private val aesKey: ByteArray,      // 32 bytes
    private val baseNonce: ByteArray,   // 12 bytes
    private val chunkSize: Int          // 0 = non-stream; >0 = stream chunk size in bytes
) {
    // -----------------------------------------------------------------------
    // Non-stream API
    // -----------------------------------------------------------------------

    /**
     * Encrypt [data] in a single shot.  Requires chunkSize == 0.
     *
     * Go: func (enc *Encryptor) Encrypt(data []byte) ([]byte, error)
     */
    fun encrypt(data: ByteArray): ByteArray {
        require(chunkSize == 0) { "encrypted in stream mode" }
        return gcmEncrypt(data, aesKey, baseNonce, null)
    }

    // -----------------------------------------------------------------------
    // Stream API
    // -----------------------------------------------------------------------

    /**
     * Encrypt a stream chunk-by-chunk.  Requires chunkSize > 0.
     *
     * Each chunk uses a fresh nonce derived by placing a big-endian uint32
     * counter in bytes [8..11] of the 12-byte nonce (bytes [0..7] come from
     * [baseNonce]).  This mirrors Go's streaming implementation.
     *
     * Go: func (enc *Encryptor) EncryptStream(ctx context.Context, in io.Reader, out io.Writer) error
     */
    fun encryptStream(input: InputStream, output: OutputStream) {
        require(chunkSize > 0) { "chunk size is not set" }

        val secretKey = SecretKeySpec(aesKey, "AES")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")

        // nonce = baseNonce[0..7] || counter(uint32, big-endian) [4 bytes]
        val nonce = ByteArray(12)
        baseNonce.copyInto(nonce, destinationOffset = 0, startIndex = 0, endIndex = 8)
        val nonceBuf = ByteBuffer.wrap(nonce) // default ByteOrder.BIG_ENDIAN

        val buf = ByteArray(chunkSize)
        var nonceIdx = 0

        while (true) {
            nonceBuf.putInt(8, nonceIdx++)

            val n = readFull(input, buf)
            if (n == 0) break   // clean EOF before any bytes

            cipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(GCM_TAG_BITS, nonce))
            val cipherText = cipher.doFinal(buf, 0, n)
            output.write(cipherText)

            if (n < chunkSize) break  // partial last chunk → done
        }
    }

    // -----------------------------------------------------------------------
    // Factory
    // -----------------------------------------------------------------------

    companion object {
        /**
         * Create an [Encryptor] for [pubKey] (compressed hex) and return it together
         * with the serialized 185-byte capsule that the owner needs to store.
         *
         * When [chunkSize] == 0 the encryptor is in non-stream mode ([encrypt]).
         * When [chunkSize] >  0 the encryptor is in stream  mode ([encryptStream]).
         *
         * Go: func NewEncryptor(pubKey string, chunkSize uint32) (*Encryptor, []byte, error)
         */
        fun create(pubKey: String, chunkSize: Int = 0): Pair<Encryptor, ByteArray> {
            val pub = publicCompressedKeyToKey(pubKey)
            val (cap, keyBytes) = generateAESKey(pub, chunkSize)
            val capsuleBytes = encodeCapsule(cap)

            // TODO: derive aesKey / baseNonce via HKDF (same note exists in the Go source)
            val enc = Encryptor(
                aesKey     = keyBytes.copyOfRange(0, 32),
                baseNonce  = keyBytes.copyOfRange(0, 12),
                chunkSize  = chunkSize
            )
            return Pair(enc, capsuleBytes)
        }
    }
}

// ---------------------------------------------------------------------------
// Internal stream helper
// ---------------------------------------------------------------------------

/**
 * Try to fill [buf] completely from [input].
 * Returns the number of bytes actually read (< buf.size means EOF was reached).
 * Mirrors Go's io.ReadFull behaviour.
 */
internal fun readFull(input: InputStream, buf: ByteArray): Int {
    var total = 0
    while (total < buf.size) {
        val n = input.read(buf, total, buf.size - total)
        if (n == -1) break
        total += n
    }
    return total
}
