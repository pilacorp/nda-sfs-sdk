package io.pilacorp.didencryption.didencrypt

import io.pilacorp.didencryption.curve.bytesToPublicKey
import io.pilacorp.didencryption.utils.hexToByteArray
import io.pilacorp.didencryption.utils.privateKeyStrToKey
import io.pilacorp.didencryption.utils.toHexString
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Holds the derived AES key and base nonce used for decryption.
 *
 * Construct via one of the factory methods:
 *  - [Decryptor.create]        — delegatee decryption (requires re-capsule)
 *  - [Decryptor.createByOwner] — owner decryption (uses original capsule)
 *  - [Decryptor.fromHex]       — reconstruct from a previously serialized hex string
 *
 * When [chunkSize] == 0 → use [decrypt] / [decryptByOwner]  (single-shot).
 * When [chunkSize] >  0 → use [decryptStream]               (streaming).
 *
 * Go: type Decryptor struct { aesKey [32]byte; baseNonce [12]byte; chunkSize uint32 }
 */
class Decryptor internal constructor(
    private val aesKey: ByteArray,      // 32 bytes
    private val baseNonce: ByteArray,   // 12 bytes
    private val chunkSize: Int          // 0 = non-stream; >0 = stream chunk size
) {
    // -----------------------------------------------------------------------
    // Non-stream API
    // -----------------------------------------------------------------------

    /**
     * Decrypt a single-shot ciphertext.  Requires chunkSize == 0.
     *
     * Go: func (d *Decryptor) Decrypt(cipherText []byte) ([]byte, error)
     */
    fun decrypt(cipherText: ByteArray): ByteArray {
        require(chunkSize == 0) { "encrypted in stream mode" }
        return gcmDecrypt(cipherText, aesKey, baseNonce, null)
    }

    /**
     * Owner variant of [decrypt] — identical behaviour (same AES key derivation path,
     * just a different constructor).
     *
     * Go: func (d *Decryptor) DecryptByOwner(cipherText []byte) ([]byte, error)
     */
    fun decryptByOwner(cipherText: ByteArray): ByteArray {
        require(chunkSize == 0) { "encrypted in stream mode" }
        return gcmDecrypt(cipherText, aesKey, baseNonce, null)
    }

    // -----------------------------------------------------------------------
    // Stream API
    // -----------------------------------------------------------------------

    /**
     * Decrypt a stream chunk-by-chunk.  Requires chunkSize > 0.
     *
     * Each encrypted chunk is (chunkSize + 16) bytes (16 = GCM auth tag).
     * The nonce counter is big-endian uint32 in bytes [8..11].
     *
     * Go: func (d *Decryptor) DecryptStream(ctx context.Context, in io.Reader, out io.Writer) error
     */
    fun decryptStream(input: InputStream, output: OutputStream) {
        require(chunkSize > 0) { "chunk size is not set" }

        val secretKey = SecretKeySpec(aesKey, "AES")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")

        val nonce = ByteArray(12)
        baseNonce.copyInto(nonce, destinationOffset = 0, startIndex = 0, endIndex = 8)
        val nonceBuf = ByteBuffer.wrap(nonce) // default ByteOrder.BIG_ENDIAN

        val encryptedChunkSize = chunkSize + GCM_TAG_BYTES
        val buf = ByteArray(encryptedChunkSize)
        var nonceIdx = 0

        while (true) {
            nonceBuf.putInt(8, nonceIdx++)

            val n = readFull(input, buf)
            if (n == 0) break   // clean EOF

            cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(GCM_TAG_BITS, nonce))
            val plainText = cipher.doFinal(buf, 0, n)
            output.write(plainText)

            if (n < encryptedChunkSize) break  // last (partial) chunk
        }
    }

    // -----------------------------------------------------------------------
    // Serialization
    // -----------------------------------------------------------------------

    /**
     * Serialize this decryptor to a hex string so it can be stored or transmitted.
     *
     * Layout (48 bytes → 96 hex chars):
     *   [32 bytes aesKey] [12 bytes baseNonce] [4 bytes chunkSize, uint32 LE]
     *
     * Go: func (d *Decryptor) Hex() (string, error)
     */
    fun toHex(): String {
        val out = ByteBuffer.allocate(32 + 12 + 4)
            .order(java.nio.ByteOrder.LITTLE_ENDIAN)
        out.put(aesKey)
        out.put(baseNonce)
        out.putInt(chunkSize)
        return out.array().toHexString()
    }

    // -----------------------------------------------------------------------
    // Factory
    // -----------------------------------------------------------------------

    companion object {
        /**
         * Reconstruct a [Decryptor] from a hex string produced by [toHex].
         *
         * Go: func NewDecryptorFromHex(hexString string) (*Decryptor, error)
         */
        fun fromHex(hexString: String): Decryptor {
            val bytes = hexString.hexToByteArray()
            require(bytes.size == 48) { "Invalid decryptor hex: expected 96 hex chars (48 bytes), got ${bytes.size}" }

            val buf = ByteBuffer.wrap(bytes).order(java.nio.ByteOrder.LITTLE_ENDIAN)
            val aesKey    = ByteArray(32).also { buf.get(it) }
            val baseNonce = ByteArray(12).also { buf.get(it) }
            val chunkSize = buf.int

            return Decryptor(aesKey, baseNonce, chunkSize)
        }

        /**
         * Create a [Decryptor] for a *delegatee* using their private key and the
         * 250-byte re-capsule produced by [createReCapsule].
         *
         * Re-capsule layout: [185 bytes re-encrypted capsule] [65 bytes ephemeral point X]
         *
         * Go: func NewDecryptor(recieverPrvKey string, reCapsule []byte) (*Decryptor, error)
         */
        fun create(receiverPrvKey: String, reCapsule: ByteArray): Decryptor {
            require(reCapsule.size == 250) { "invalid share data key: expected 250 bytes, got ${reCapsule.size}" }

            val prvKeyD = privateKeyStrToKey(receiverPrvKey)
            val cap     = decodeCapsule(reCapsule.copyOfRange(0, 185))
            val pubX    = bytesToPublicKey(reCapsule.copyOfRange(185, 250))

            val keyBytes = decryptAESKey(prvKeyD, cap, pubX)

            return Decryptor(
                aesKey    = keyBytes.copyOfRange(0, 32),
                baseNonce = keyBytes.copyOfRange(0, 12),
                chunkSize = cap.chunkSize
            )
        }

        /**
         * Create a [Decryptor] for the *owner* using their private key and the
         * original 185-byte capsule.
         *
         * Go: func NewDecryptorByOwner(ownerPrvKey string, capsule []byte) (*Decryptor, error)
         */
        fun createByOwner(ownerPrvKey: String, capsule: ByteArray): Decryptor {
            require(capsule.size == 185) { "invalid original capsule: expected 185 bytes, got ${capsule.size}" }

            val prvKeyD  = privateKeyStrToKey(ownerPrvKey)
            val cap      = decodeCapsule(capsule)
            val keyBytes = decryptAESKeyByOwner(prvKeyD, cap)

            return Decryptor(
                aesKey    = keyBytes.copyOfRange(0, 32),
                baseNonce = keyBytes.copyOfRange(0, 12),
                chunkSize = cap.chunkSize
            )
        }
    }
}
