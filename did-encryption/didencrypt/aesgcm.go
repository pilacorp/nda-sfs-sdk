package didencrypt

import (
	"crypto/aes"
	"crypto/cipher"
)

func gmcEncrypt(plaintext []byte, key [32]byte, iv []byte, additionalData []byte) (cipherText []byte, err error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	cipherText = aesgcm.Seal(nil, iv, plaintext, additionalData)

	return cipherText, nil
}

func gcmDecrypt(cipherText []byte, key [32]byte, iv []byte, additionalData []byte) (plainText []byte, err error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plainText, err = aesgcm.Open(nil, iv, cipherText, additionalData)
	if err != nil {
		return nil, err
	}

	return plainText, nil
}
