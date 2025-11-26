package didencrypt

import (
	"testing"

	"github.com/pilacorp/did-encryption/utils"
)

// TestE2E tests the complete encryption and decryption flow
func TestE2E(t *testing.T) {
	// Generate key pairs for Alice and Bob
	alicePrivKey, alicePubKey, err := utils.GenerateKeys()
	if err != nil {
		t.Fatalf("Failed to generate Alice's keys: %v", err)
	}

	bobPrivKey, bobPubKey, err := utils.GenerateKeys()
	if err != nil {
		t.Fatalf("Failed to generate Bob's keys: %v", err)
	}

	// Test data
	testData := []byte("Hello, World! This is a test message for proxy re-encryption. Hello, World! This is a test message for proxy re-encryption.  Hello, World! This is a test message for proxy re-encryption. ")
	t.Logf("Original data: %s", string(testData))

	aliceEncryptor, capsule, err := NewEncryptor(utils.PublicKeyToCompressedKey(alicePubKey), 0)
	if err != nil {
		t.Fatalf("Failed to create Alice's encryptor: %v", err)
	}

	// Step 1: Alice encrypts data for herself
	cipherText, err := aliceEncryptor.Encrypt(testData)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
	t.Logf("Encryption successful. Capsule size: %d bytes, Cipher text size: %d bytes", len(capsule), len(cipherText))

	// Step 2: Alice creates a re-encryption key for Bob
	shareDataKey, err := CreateReCapsule(utils.PrivateKeyToHexString(alicePrivKey), utils.PublicKeyToCompressedKey(bobPubKey), capsule)
	if err != nil {
		t.Fatalf("Failed to create share data key: %v", err)
	}
	t.Logf("Share data key created successfully. Size: %d bytes", len(shareDataKey))

	bobDecryptor, err := NewDecryptor(utils.PrivateKeyToHexString(bobPrivKey), shareDataKey)
	if err != nil {
		t.Fatalf("Failed to create Bob's decryptor: %v", err)
	}

	hex, err := bobDecryptor.Hex()
	if err != nil {
		t.Fatalf("Failed to get Bob's decryptor hex: %v", err)
	}

	t.Logf("Bob's decryptor hex: %s", hex)

	bobDecryptorFromHex, err := NewDecryptorFromHex(hex)
	if err != nil {
		t.Fatalf("Failed to create Bob's decryptor from hex: %v", err)
	}

	hexFromBobDecryptorFromHex, err := bobDecryptorFromHex.Hex()
	if err != nil {
		t.Fatalf("Failed to get Bob's decryptor from hex: %v", err)
	}

	if hex != hexFromBobDecryptorFromHex {
		t.Fatalf("Bob's decryptor hex doesn't match")
	}

	// Step 3: Bob decrypts the data using the share data key
	decryptedData, err := bobDecryptorFromHex.Decrypt(cipherText)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	aliceDecryptor, err := NewDecryptorByOwner(utils.PrivateKeyToHexString(alicePrivKey), capsule)
	if err != nil {
		t.Fatalf("Failed to create Alice's decryptor: %v", err)
	}

	hex, err = aliceDecryptor.Hex()
	if err != nil {
		t.Fatalf("Failed to get Alice's decryptor hex: %v", err)
	}

	t.Logf("Alice's decryptor hex: %s", hex)

	aliceDecryptorFromHex, err := NewDecryptorFromHex(hex)
	if err != nil {
		t.Fatalf("Failed to create Alice's decryptor from hex: %v", err)
	}

	// Step 4: owner decrypts the data using the original capsule
	decryptedOwnerData, err := aliceDecryptorFromHex.DecryptByOwner(cipherText)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Verify the decrypted data matches the original
	if string(decryptedData) != string(testData) {
		t.Errorf("Decrypted data doesn't match original. Expected: %s, Got: %s", string(testData), string(decryptedData))
	} else {
		t.Logf("Decryption successful. Decrypted data: %s", string(decryptedData))
		t.Logf("Decryption successful. Decrypted owner data: %s", string(decryptedOwnerData))
	}
}
