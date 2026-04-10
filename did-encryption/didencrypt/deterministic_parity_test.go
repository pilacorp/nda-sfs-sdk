package didencrypt

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/pilacorp/nda-sfs-sdk/did-encryption/curve"
	"github.com/pilacorp/nda-sfs-sdk/did-encryption/utils"
)

func repeatedHexByte(b byte) string {
	return strings.Repeat(fmt.Sprintf("%02x", b), 32)
}

func logStep(t *testing.T, name string, value []byte) {
	t.Helper()
	t.Logf("STEP|%s|%s", name, hex.EncodeToString(value))
}

func logStepString(t *testing.T, name string, value string) {
	t.Helper()
	t.Logf("STEP|%s|%s", name, value)
}

func TestDeterministicParityVector(t *testing.T) {
	ownerPriv, err := utils.PrivateKeyStrToKey(repeatedHexByte(0x11))
	if err != nil {
		t.Fatalf("owner private key: %v", err)
	}
	receiverPriv, err := utils.PrivateKeyStrToKey(repeatedHexByte(0x22))
	if err != nil {
		t.Fatalf("receiver private key: %v", err)
	}
	encryptEPriv, err := utils.PrivateKeyStrToKey(repeatedHexByte(0x33))
	if err != nil {
		t.Fatalf("encrypt E private key: %v", err)
	}
	encryptVPriv, err := utils.PrivateKeyStrToKey(repeatedHexByte(0x44))
	if err != nil {
		t.Fatalf("encrypt V private key: %v", err)
	}
	rekeyXPriv, err := utils.PrivateKeyStrToKey(repeatedHexByte(0x55))
	if err != nil {
		t.Fatalf("rekey X private key: %v", err)
	}

	ownerPubHex := utils.PublicKeyToCompressedKey(&ownerPriv.PublicKey)
	receiverPubHex := utils.PublicKeyToCompressedKey(&receiverPriv.PublicKey)
	encryptEPubHex := utils.PublicKeyToCompressedKey(&encryptEPriv.PublicKey)
	encryptVPubHex := utils.PublicKeyToCompressedKey(&encryptVPriv.PublicKey)
	rekeyXPubHex := utils.PublicKeyToCompressedKey(&rekeyXPriv.PublicKey)

	message := []byte("Cross-language deterministic test payload.")
	var chunkSize uint32 = 16

	logStepString(t, "ownerPrivateKey", repeatedHexByte(0x11))
	logStepString(t, "ownerPublicKey", ownerPubHex)
	logStepString(t, "receiverPrivateKey", repeatedHexByte(0x22))
	logStepString(t, "receiverPublicKey", receiverPubHex)
	logStepString(t, "encryptEPrivateKey", repeatedHexByte(0x33))
	logStepString(t, "encryptEPublicKey", encryptEPubHex)
	logStepString(t, "encryptVPrivateKey", repeatedHexByte(0x44))
	logStepString(t, "encryptVPublicKey", encryptVPubHex)
	logStepString(t, "rekeyXPrivateKey", repeatedHexByte(0x55))
	logStepString(t, "rekeyXPublicKey", rekeyXPubHex)
	logStep(t, "plaintext", message)

	encryptEPub, err := utils.PublicCompressedKeyToKey(encryptEPubHex)
	if err != nil {
		t.Fatalf("encrypt E public key: %v", err)
	}
	encryptVPub, err := utils.PublicCompressedKeyToKey(encryptVPubHex)
	if err != nil {
		t.Fatalf("encrypt V public key: %v", err)
	}
	rekeyXPub, err := utils.PublicCompressedKeyToKey(rekeyXPubHex)
	if err != nil {
		t.Fatalf("rekey X public key: %v", err)
	}

	h := utils.HashToCurve(utils.ConcatBytes(curve.PointToBytes(encryptEPub), curve.PointToBytes(encryptVPub)))
	s := curve.BigIntAdd(encryptVPriv.D, curve.BigIntMul(encryptEPriv.D, h))
	sum := curve.BigIntAdd(encryptEPriv.D, encryptVPriv.D)
	sharedPoint := curve.PointScalarMul(&ownerPriv.PublicKey, sum)
	keyBytes, err := utils.Sha3Hash(curve.PointToBytes(sharedPoint))
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}

	capSingle := &capsule{
		E:         encryptEPub,
		V:         encryptVPub,
		S:         s,
		ChunkSize: 0,
		Version:   0,
	}
	capStream := &capsule{
		E:         encryptEPub,
		V:         encryptVPub,
		S:         s,
		ChunkSize: chunkSize,
		Version:   0,
	}
	capsuleSingleBytes, err := encodeCapsule(capSingle)
	if err != nil {
		t.Fatalf("encode capsule single: %v", err)
	}
	capsuleStreamBytes, err := encodeCapsule(capStream)
	if err != nil {
		t.Fatalf("encode capsule stream: %v", err)
	}

	logStep(t, "capsuleSingle", capsuleSingleBytes)
	logStep(t, "capsuleStream", capsuleStreamBytes)
	logStep(t, "aesKey", keyBytes[:32])
	logStep(t, "baseNonce", keyBytes[:12])

	var aesKey [32]byte
	copy(aesKey[:], keyBytes[:32])
	var baseNonce [12]byte
	copy(baseNonce[:], keyBytes[:12])

	singleCipher, err := gmcEncrypt(message, aesKey, baseNonce[:], nil)
	if err != nil {
		t.Fatalf("single encrypt: %v", err)
	}
	logStep(t, "singleCiphertext", singleCipher)

	singlePlain, err := gcmDecrypt(singleCipher, aesKey, baseNonce[:], nil)
	if err != nil {
		t.Fatalf("single decrypt: %v", err)
	}
	if !bytes.Equal(singlePlain, message) {
		t.Fatalf("single plaintext mismatch")
	}

	pointX := curve.PointScalarMul(&receiverPriv.PublicKey, rekeyXPriv.D)
	d := utils.HashToCurve(
		utils.ConcatBytes(
			utils.ConcatBytes(
				curve.PointToBytes(rekeyXPub),
				curve.PointToBytes(&receiverPriv.PublicKey)),
			curve.PointToBytes(pointX)),
	)
	rk := curve.BigIntMul(ownerPriv.D, curve.GetInvert(d))
	reCapSingle, err := reEncryption(rk, capSingle)
	if err != nil {
		t.Fatalf("re-encryption single: %v", err)
	}
	reCapStream, err := reEncryption(rk, capStream)
	if err != nil {
		t.Fatalf("re-encryption stream: %v", err)
	}
	reCapsuleSingleBytes, err := encodeCapsule(reCapSingle)
	if err != nil {
		t.Fatalf("encode re-capsule single: %v", err)
	}
	reCapsuleSingleBytes = append(reCapsuleSingleBytes, curve.PointToBytes(rekeyXPub)...)
	reCapsuleStreamBytes, err := encodeCapsule(reCapStream)
	if err != nil {
		t.Fatalf("encode re-capsule stream: %v", err)
	}
	reCapsuleStreamBytes = append(reCapsuleStreamBytes, curve.PointToBytes(rekeyXPub)...)
	logStep(t, "reCapsuleSingle", reCapsuleSingleBytes)
	logStep(t, "reCapsuleStream", reCapsuleStreamBytes)

	receiverDecSingle, err := NewDecryptor(repeatedHexByte(0x22), reCapsuleSingleBytes)
	if err != nil {
		t.Fatalf("receiver decryptor single: %v", err)
	}
	ownerDecSingle, err := NewDecryptorByOwner(repeatedHexByte(0x11), capsuleSingleBytes)
	if err != nil {
		t.Fatalf("owner decryptor single: %v", err)
	}

	receiverPlain, err := receiverDecSingle.Decrypt(singleCipher)
	if err != nil {
		t.Fatalf("receiver decrypt: %v", err)
	}
	ownerPlain, err := ownerDecSingle.DecryptByOwner(singleCipher)
	if err != nil {
		t.Fatalf("owner decrypt: %v", err)
	}
	logStep(t, "receiverPlaintext", receiverPlain)
	logStep(t, "ownerPlaintext", ownerPlain)
	if !bytes.Equal(receiverPlain, message) || !bytes.Equal(ownerPlain, message) {
		t.Fatalf("single-message round trip mismatch")
	}

	streamEnc := &Encryptor{
		aesKey:    aesKey,
		baseNonce: baseNonce,
		chunkSize: chunkSize,
	}
	streamIn := bytes.NewReader(message)
	streamOut := bytes.NewBuffer(nil)
	if err := streamEnc.EncryptStream(context.Background(), streamIn, streamOut); err != nil {
		t.Fatalf("stream encrypt: %v", err)
	}
	streamCipher := streamOut.Bytes()
	logStep(t, "streamCiphertext", streamCipher)

	receiverDecStream, err := NewDecryptor(repeatedHexByte(0x22), reCapsuleStreamBytes)
	if err != nil {
		t.Fatalf("receiver decryptor stream: %v", err)
	}
	ownerDecStream, err := NewDecryptorByOwner(repeatedHexByte(0x11), capsuleStreamBytes)
	if err != nil {
		t.Fatalf("owner decryptor stream: %v", err)
	}

	receiverStreamOut := bytes.NewBuffer(nil)
	if err := receiverDecStream.DecryptStream(context.Background(), bytes.NewReader(streamCipher), receiverStreamOut); err != nil {
		t.Fatalf("receiver stream decrypt: %v", err)
	}
	ownerStreamOut := bytes.NewBuffer(nil)
	if err := ownerDecStream.DecryptStream(context.Background(), bytes.NewReader(streamCipher), ownerStreamOut); err != nil {
		t.Fatalf("owner stream decrypt: %v", err)
	}
	logStep(t, "receiverStreamPlaintext", receiverStreamOut.Bytes())
	logStep(t, "ownerStreamPlaintext", ownerStreamOut.Bytes())
	if !bytes.Equal(receiverStreamOut.Bytes(), message) || !bytes.Equal(ownerStreamOut.Bytes(), message) {
		t.Fatalf("stream round trip mismatch")
	}
}
