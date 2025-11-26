package utils

import (
	"crypto/ecdsa"
	"encoding/hex"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
)

func GenerateKeys() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, nil, err
	}

	return privateKey, &privateKey.PublicKey, nil
}

func PrivateKeyStrToKey(hexKey string) (*ecdsa.PrivateKey, error) {
	return crypto.HexToECDSA(strings.TrimPrefix(hexKey, "0x"))
}

func PrivateKeyToHexString(priv *ecdsa.PrivateKey) string {
	return hex.EncodeToString(crypto.FromECDSA(priv))
}

func PublicKeyToCompressedKey(pub *ecdsa.PublicKey) string {
	return hex.EncodeToString(crypto.CompressPubkey(pub))
}

func PublicCompressedKeyToKey(hexPub string) (*ecdsa.PublicKey, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(hexPub, "0x"))
	if err != nil {
		return nil, err
	}
	return crypto.DecompressPubkey(b)
}
