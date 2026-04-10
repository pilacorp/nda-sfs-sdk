package io.pilacorp.didencryption

import io.pilacorp.didencryption.didencrypt.Decryptor
import io.pilacorp.didencryption.didencrypt.Encryptor
import io.pilacorp.didencryption.didencrypt.createReCapsule
import io.pilacorp.didencryption.utils.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

class RecryptTest {

    // -----------------------------------------------------------------------
    // Non-stream (single-shot) E2E test
    // -----------------------------------------------------------------------

    @Test
    fun `E2E non-stream encryption and decryption`() {
        // Generate key pairs for Alice (owner) and Bob (delegate)
        val (alicePrivKey, alicePubKey) = generateKeys()
        val (bobPrivKey,   bobPubKey)   = generateKeys()

        val testData = "Hello, World! This is a test message for proxy re-encryption.".toByteArray()

        // Step 1: Alice creates an encryptor and encrypts data for herself
        val (aliceEncryptor, capsule) = Encryptor.create(publicKeyToCompressedKey(alicePubKey), chunkSize = 0)
        val cipherText = aliceEncryptor.encrypt(testData)

        println("Capsule size   : ${capsule.size} bytes")   // expect 185
        println("CipherText size: ${cipherText.size} bytes")

        // Step 2: Alice creates a re-capsule for Bob
        val shareDataKey = createReCapsule(
            privateKeyToHexString(alicePrivKey),
            publicKeyToCompressedKey(bobPubKey),
            capsule
        )
        println("ShareDataKey size: ${shareDataKey.size} bytes")  // expect 250
        assertEquals(250, shareDataKey.size, "Re-capsule must be 250 bytes")

        // Step 3: Bob creates a decryptor from the share data key
        val bobDecryptor = Decryptor.create(privateKeyToHexString(bobPrivKey), shareDataKey)

        // Round-trip through hex serialization
        val bobHex = bobDecryptor.toHex()
        println("Bob's decryptor hex: $bobHex")
        val bobDecryptorFromHex = Decryptor.fromHex(bobHex)
        assertEquals(bobHex, bobDecryptorFromHex.toHex(), "Hex round-trip must be stable")

        // Step 4: Bob decrypts
        val decryptedByBob = bobDecryptorFromHex.decrypt(cipherText)
        assertArrayEquals(testData, decryptedByBob, "Bob's decryption must match original")
        println("Bob decrypted: ${String(decryptedByBob)}")

        // Step 5: Alice decrypts as owner
        val aliceDecryptor = Decryptor.createByOwner(privateKeyToHexString(alicePrivKey), capsule)
        val aliceHex = aliceDecryptor.toHex()
        val aliceDecryptorFromHex = Decryptor.fromHex(aliceHex)

        val decryptedByAlice = aliceDecryptorFromHex.decryptByOwner(cipherText)
        assertArrayEquals(testData, decryptedByAlice, "Alice's (owner) decryption must match original")
        println("Alice decrypted: ${String(decryptedByAlice)}")
    }

    // -----------------------------------------------------------------------
    // Stream E2E test
    // -----------------------------------------------------------------------

    @Test
    fun `E2E stream encryption and decryption`() {
        val (alicePrivKey, alicePubKey) = generateKeys()
        val (bobPrivKey,   bobPubKey)   = generateKeys()

        // Construct a test payload that spans multiple chunks
        val chunkSize = 2
        val testData = "Hello, World! This is a streaming PRE test.".toByteArray()

        val inputStream = ByteArrayInputStream(testData)
        val cipherBuf   = ByteArrayOutputStream()

        // Step 1: Alice encrypts the stream
        val (aliceEncryptor, capsule) = Encryptor.create(publicKeyToCompressedKey(alicePubKey), chunkSize)
        aliceEncryptor.encryptStream(inputStream, cipherBuf)

        // Step 2: Alice creates a re-capsule for Bob
        val shareDataKey = createReCapsule(
            privateKeyToHexString(alicePrivKey),
            publicKeyToCompressedKey(bobPubKey),
            capsule
        )
        assertEquals(250, shareDataKey.size, "Re-capsule must be 250 bytes")

        // Step 3: Bob creates decryptor, hex round-trip
        val bobDecryptor = Decryptor.create(privateKeyToHexString(bobPrivKey), shareDataKey)
        val bobHex = bobDecryptor.toHex()
        val bobDecryptorFromHex = Decryptor.fromHex(bobHex)

        // Step 4: Bob decrypts the stream
        val plainBuf = ByteArrayOutputStream()
        bobDecryptorFromHex.decryptStream(ByteArrayInputStream(cipherBuf.toByteArray()), plainBuf)

        assertArrayEquals(testData, plainBuf.toByteArray(), "Stream decryption must match original")
        println("Stream decrypted: ${String(plainBuf.toByteArray())}")
    }

    @Test
    fun `E2E stream owner decryption`() {
        val (alicePrivKey, alicePubKey) = generateKeys()

        val chunkSize = 64
        val testData = "Owner stream decryption test data!".repeat(5).toByteArray()

        val cipherBuf = ByteArrayOutputStream()
        val (encryptor, capsule) = Encryptor.create(publicKeyToCompressedKey(alicePubKey), chunkSize)
        encryptor.encryptStream(ByteArrayInputStream(testData), cipherBuf)

        val aliceDecryptor = Decryptor.createByOwner(privateKeyToHexString(alicePrivKey), capsule)
        val aliceHex = aliceDecryptor.toHex()
        val aliceDecryptorFromHex = Decryptor.fromHex(aliceHex)

        val plainBuf = ByteArrayOutputStream()
        aliceDecryptorFromHex.decryptStream(ByteArrayInputStream(cipherBuf.toByteArray()), plainBuf)

        assertArrayEquals(testData, plainBuf.toByteArray(), "Owner stream decryption must match original")
    }

    // -----------------------------------------------------------------------
    // Capsule size sanity checks
    // -----------------------------------------------------------------------

    @Test
    fun `capsule is exactly 185 bytes`() {
        val (_, pub) = generateKeys()
        val (_, capsule) = Encryptor.create(publicKeyToCompressedKey(pub), 0)
        assertEquals(185, capsule.size, "Capsule must be exactly 185 bytes")
    }

    @Test
    fun `re-capsule is exactly 250 bytes`() {
        val (alicePriv, alicePub) = generateKeys()
        val (_, bobPub)           = generateKeys()
        val (_, capsule)          = Encryptor.create(publicKeyToCompressedKey(alicePub), 0)
        val reCapBytes = createReCapsule(
            privateKeyToHexString(alicePriv),
            publicKeyToCompressedKey(bobPub),
            capsule
        )
        assertEquals(250, reCapBytes.size, "Re-capsule must be exactly 250 bytes")
    }

    // -----------------------------------------------------------------------
    // Key serialization round-trips
    // -----------------------------------------------------------------------

    @Test
    fun `private key hex round-trip`() {
        val (priv, _) = generateKeys()
        val hex  = privateKeyToHexString(priv)
        val back = privateKeyStrToKey(hex)
        assertEquals(priv, back)
    }

    @Test
    fun `compressed public key round-trip`() {
        val (_, pub) = generateKeys()
        val hex  = publicKeyToCompressedKey(pub)
        val back = publicCompressedKeyToKey(hex)
        assertEquals(pub.normalize().affineXCoord.toBigInteger(),
                     back.normalize().affineXCoord.toBigInteger())
        assertEquals(pub.normalize().affineYCoord.toBigInteger(),
                     back.normalize().affineYCoord.toBigInteger())
    }
}
