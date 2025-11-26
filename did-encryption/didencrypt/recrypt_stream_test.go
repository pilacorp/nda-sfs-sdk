package didencrypt

import (
	"bytes"
	"context"
	"testing"

	"github.com/pilacorp/did-encryption/utils"
)

func TestE2EStream(t *testing.T) {
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

	encryptReader := bytes.NewReader(testData)
	encryptWriter := bytes.NewBuffer(nil)

	aliceEncryptor, capsule, err := NewEncryptor(utils.PublicKeyToCompressedKey(alicePubKey), 2)
	if err != nil {
		t.Fatalf("Failed to create Alice's encryptor: %v", err)
	}

	// Step 1: Alice encrypts the stream
	err = aliceEncryptor.EncryptStream(context.Background(), encryptReader, encryptWriter)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Step 2: Alice creates a re-encryption key for Bob
	shareDataKey, err := CreateReCapsule(utils.PrivateKeyToHexString(alicePrivKey), utils.PublicKeyToCompressedKey(bobPubKey), capsule)
	if err != nil {
		t.Fatalf("Failed to create share data key: %v", err)
	}

	t.Logf("Share data key created successfully. Size: %d bytes", len(shareDataKey))

	bodDecryptor, err := NewDecryptor(utils.PrivateKeyToHexString(bobPrivKey), shareDataKey)
	if err != nil {
		t.Fatalf("Failed to create Bob's decryptor: %v", err)
	}

	hex, err := bodDecryptor.Hex()
	if err != nil {
		t.Fatalf("Failed to get Bob's decryptor hex: %v", err)
	}

	t.Logf("Bob's decryptor hex: %s", hex)

	bodDecryptorFromHex, err := NewDecryptorFromHex(hex)
	if err != nil {
		t.Fatalf("Failed to create Bob's decryptor from hex: %v", err)
	}

	// Step 3: Bob decrypts the stream
	decryptWriter := bytes.NewBuffer(nil)
	err = bodDecryptorFromHex.DecryptStream(context.Background(), encryptWriter, decryptWriter)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	t.Logf("Decryption successful. Decrypted data: %s", decryptWriter.String())

	encryptOwnerReader := bytes.NewReader(testData)
	encryptOwnerWriter := bytes.NewBuffer(nil)

	newAliceEncryptor, capsule, err := NewEncryptor(utils.PublicKeyToCompressedKey(alicePubKey), 2)
	if err != nil {
		t.Fatalf("Failed to create Alice's encryptor: %v", err)
	}

	// Step 4: Alice encrypts the stream
	err = newAliceEncryptor.EncryptStream(context.Background(), encryptOwnerReader, encryptOwnerWriter)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
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

	// Step 5: owner decrypts the stream
	decryptWriterOwner := bytes.NewBuffer(nil)
	err = aliceDecryptorFromHex.DecryptStream(context.Background(), encryptOwnerWriter, decryptWriterOwner)
	if err != nil {
		t.Fatalf("Decryption Owner failed: %v", err)
	}

	t.Logf("Decryption successful. Decrypted owner data: %s", decryptWriterOwner.String())
}
