package main

import (
	"bytes"
	"context"
	"fmt"
	"log"

	pre "github.com/pilacorp/did-encryption/didencrypt"
	"github.com/pilacorp/did-encryption/utils"
)

func main() {
	aliceSK, alicePK, err := utils.GenerateKeys()
	if err != nil {
		log.Fatalf("generate alice keys: %v", err)
	}
	bobSK, bobPK, err := utils.GenerateKeys()
	if err != nil {
		log.Fatalf("generate bob keys: %v", err)
	}

	// Prepare an input stream (here we fake a large file with repeated bytes).
	inputData := bytes.Repeat([]byte("streaming-encryption-"), 1024)
	inputReader := bytes.NewReader(inputData)

	var cipherBuf bytes.Buffer
	chunkSize := uint32(64 * 1024) // 64 KiB frames

	aliceEncryptor, capsule, err := pre.NewEncryptor(utils.PublicKeyToCompressedKey(alicePK), chunkSize)
	if err != nil {
		log.Fatalf("create alice encryptor: %v", err)
	}

	err = aliceEncryptor.EncryptStream(context.Background(), inputReader, &cipherBuf)
	if err != nil {
		log.Fatalf("encrypt stream: %v", err)
	}

	shareDataKey, err := pre.CreateReCapsule(utils.PrivateKeyToHexString(aliceSK), utils.PublicKeyToCompressedKey(bobPK), capsule)
	if err != nil {
		log.Fatalf("create share data key: %v", err)
	}

	bobDecryptor, err := pre.NewDecryptor(utils.PrivateKeyToHexString(bobSK), shareDataKey)
	if err != nil {
		log.Fatalf("create bob decryptor: %v", err)
	}

	hex, err := bobDecryptor.Hex()
	if err != nil {
		log.Fatalf("Failed to get Bob's decryptor hex: %v", err)
	}

	bobDecryptorFromHex, err := pre.NewDecryptorFromHex(hex)
	if err != nil {
		log.Fatalf("Failed to create Bob's decryptor from hex: %v", err)
	}

	var plainBuf bytes.Buffer
	if err := bobDecryptorFromHex.DecryptStream(context.Background(), bytes.NewReader(cipherBuf.Bytes()), &plainBuf); err != nil {
		log.Fatalf("decrypt stream: %v", err)
	}

	if !bytes.Equal(inputData, plainBuf.Bytes()) {
		log.Fatal("decrypted stream does not match original data")
	}

	fmt.Printf("Stream decrypt succeeded, recovered %d bytes\n", plainBuf.Len())
}
