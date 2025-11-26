# DID-Encryption SDK (Go)

Go implementation of an NDA-focused proxy re-encryption workflow. The package
allows you to:

- Encrypt data for a data owner (Alice) and create a **capsule**.
- Derive a re-encryption key so a proxy can transform the capsule for a delegate
  (Bob).
- Let Bob decrypt the re-encrypted ciphertext using his own secret key.
- Optionally encrypt data streams in fixed-size chunks.

> **Module import:** `github.com/pilacorp/did-encryption`

## Installation

```bash
go get github.com/pilacorp/did-encryption
```

The module exposes packages under `pre`, `utils`, and `curve`. For most use
cases you only need `pre` and `utils`.

## Basic example

The `examples/basic` folder contains a runnable sample:

```go
package main

import (
	"fmt"
	"log"

	"github.com/pilacorp/did-encryption/didencrypt"
	"github.com/pilacorp/did-encryption/utils"
)

func main() {
	// Generate long-term keys for Alice (data owner) and Bob (delegate).
	aliceSK, alicePK, err := utils.GenerateKeys()
	if err != nil {
		log.Fatalf("generate alice keys: %v", err)
	}

	bobSK, bobPK, err := utils.GenerateKeys()
	if err != nil {
		log.Fatalf("generate bob keys: %v", err)
	}

	message := []byte("NDA DID Encryption with NDA SDK in Go")

	// 1) Create an encryptor for Alice (chunkSize = 0 for single message encryption)
	aliceEncryptor, capsule, err := didencrypt.NewEncryptor(utils.PublicKeyToCompressedKey(alicePK), 0)
	if err != nil {
		log.Fatalf("create alice encryptor: %v", err)
	}

	// 2) Alice encrypts for herself. The result is the ciphertext and a capsule.
	ciphertext, err := aliceEncryptor.Encrypt(message)
	if err != nil {
		log.Fatalf("encrypt: %v", err)
	}

	// 3) Alice derives a share key for Bob. She can send this shareDataKey to the proxy.
	shareDataKey, err := didencrypt.CreateShareDataKey(
		utils.PrivateKeyToHexString(aliceSK),
		utils.PublicKeyToCompressedKey(bobPK),
		capsule,
	)
	if err != nil {
		log.Fatalf("create share data key: %v", err)
	}

	// 4) Create a decryptor for Bob
	bobDecryptor, err := didencrypt.NewDecryptor(
		utils.PrivateKeyToHexString(bobSK),
		shareDataKey,
	)
	if err != nil {
		log.Fatalf("create bob decryptor: %v", err)
	}

	// 5) Bob uses the decryptor to decrypt the ciphertext
	plaintext, err := bobDecryptor.Decrypt(ciphertext)
	if err != nil {
		log.Fatalf("decrypt: %v", err)
	}

	fmt.Printf("Original message : %s\n", message)
	fmt.Printf("Recovered message: %s\n", plaintext)
}
```

Run it with:

```bash
go run ./examples/basic
```

## Decryptor Serialization

The decryptor can be serialized to hex format for storage or transmission:

```go
// Serialize decryptor to hex
hex, err := bobDecryptor.Hex()
if err != nil {
	log.Fatalf("Failed to serialize decryptor: %v", err)
}

// Reconstruct decryptor from hex
bobDecryptorFromHex, err := didencrypt.NewDecryptorFromHex(hex)
if err != nil {
	log.Fatalf("Failed to create decryptor from hex: %v", err)
}

// Use the reconstructed decryptor
plaintext, err := bobDecryptorFromHex.Decrypt(ciphertext)
```

## Owner Decryption

The data owner (Alice) can decrypt their own encrypted data using the original capsule:

```go
// Create decryptor for the owner
aliceDecryptor, err := didencrypt.NewDecryptorByOwner(
	utils.PrivateKeyToHexString(aliceSK),
	capsule,
)
if err != nil {
	log.Fatalf("create alice decryptor: %v", err)
}

// Decrypt using owner's decryptor
plaintext, err := aliceDecryptor.DecryptByOwner(ciphertext)
```

## Streaming support

Package `pre` also exposes `EncryptStream` / `DecryptStream` for large files. These helpers break data into fixed-size chunks, encrypt each chunk with AES-GCM using unique nonces, and store chunk metadata inside the capsule. The companion example `examples/stream/main.go` demonstrates the full flow:

```go
aliceSK, alicePK, err := utils.GenerateKeys()
if err != nil {
	log.Fatalf("generate alice keys: %v", err)
}
bobSK, bobPK, err := utils.GenerateKeys()
if err != nil {
	log.Fatalf("generate bob keys: %v", err)
}

// Prepare an input stream
inputData := bytes.Repeat([]byte("streaming-encryption-"), 1024)
inputReader := bytes.NewReader(inputData)

var cipherBuf bytes.Buffer
chunkSize := uint32(64 * 1024) // 64 KiB frames

// Create encryptor with chunk size for streaming
aliceEncryptor, capsule, err := didencrypt.NewEncryptor(
	utils.PublicKeyToCompressedKey(alicePK),
	chunkSize,
)
if err != nil {
	log.Fatalf("create alice encryptor: %v", err)
}

// Encrypt the stream
err = aliceEncryptor.EncryptStream(context.Background(), inputReader, &cipherBuf)
if err != nil {
	log.Fatalf("encrypt stream: %v", err)
}

// Create share data key for Bob
shareDataKey, err := didencrypt.CreateShareDataKey(
	utils.PrivateKeyToHexString(aliceSK),
	utils.PublicKeyToCompressedKey(bobPK),
	capsule,
)
if err != nil {
	log.Fatalf("create share data key: %v", err)
}

// Create decryptor for Bob
bobDecryptor, err := didencrypt.NewDecryptor(
	utils.PrivateKeyToHexString(bobSK),
	shareDataKey,
)
if err != nil {
	log.Fatalf("create bob decryptor: %v", err)
}

// Decrypt the stream
var plainBuf bytes.Buffer
err = bobDecryptor.DecryptStream(
	context.Background(),
	bytes.NewReader(cipherBuf.Bytes()),
	&plainBuf,
	shareDataKey,
)
if err != nil {
	log.Fatalf("decrypt stream: %v", err)
}
```

`chunkSize` defines the frame size used during encryption. Capsule metadata keeps track of the chunk size so that the decryptor can reconstruct the stream. For owner decryption of streams, use `DecryptStreamByOwner`:

```go
aliceDecryptor, err := didencrypt.NewDecryptorByOwner(
	utils.PrivateKeyToHexString(aliceSK),
	capsule,
)
if err != nil {
	log.Fatalf("create alice decryptor: %v", err)
}

var plainBuf bytes.Buffer
err = aliceDecryptor.DecryptStreamByOwner(
	context.Background(),
	bytes.NewReader(cipherBuf.Bytes()),
	&plainBuf,
)
```

## Testing

```bash
go test ./...
```

## License

GPL-3.0

