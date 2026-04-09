package io.pilacorp.didencryption.didencrypt

import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

// AES-GCM tag length in bits (= 16 bytes overhead per chunk, matches Go's aesgcm.Overhead())
internal const val GCM_TAG_BITS = 128
internal const val GCM_TAG_BYTES = GCM_TAG_BITS / 8  // 16

/**
 * Encrypt [plaintext] with AES-256-GCM.
 *
 * Output layout: ciphertext || 16-byte GCM auth tag  (Java appends tag automatically).
 * Matches Go's aesgcm.Seal(nil, iv, plaintext, additionalData).
 *
 * Go: func gmcEncrypt(plaintext []byte, key [32]byte, iv []byte, additionalData []byte)
 */
internal fun gcmEncrypt(
    plaintext: ByteArray,
    key: ByteArray,
    iv: ByteArray,
    additionalData: ByteArray?
): ByteArray {
    val secretKey = SecretKeySpec(key, "AES")
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(GCM_TAG_BITS, iv))
    additionalData?.let { cipher.updateAAD(it) }
    return cipher.doFinal(plaintext)
}

/**
 * Decrypt [cipherText] with AES-256-GCM.
 *
 * Input layout: ciphertext || 16-byte GCM auth tag  (Java strips tag automatically).
 * Throws [javax.crypto.AEADBadTagException] if the auth tag does not match.
 * Matches Go's aesgcm.Open(nil, iv, cipherText, additionalData).
 *
 * Go: func gcmDecrypt(cipherText []byte, key [32]byte, iv []byte, additionalData []byte)
 */
internal fun gcmDecrypt(
    cipherText: ByteArray,
    key: ByteArray,
    iv: ByteArray,
    additionalData: ByteArray?
): ByteArray {
    val secretKey = SecretKeySpec(key, "AES")
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(GCM_TAG_BITS, iv))
    additionalData?.let { cipher.updateAAD(it) }
    return cipher.doFinal(cipherText)
}
