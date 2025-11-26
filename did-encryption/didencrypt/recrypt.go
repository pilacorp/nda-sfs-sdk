package didencrypt

import "fmt"

// Encrypt encrypts the data using the encryptor and returns the cipher text.
func (enc *Encryptor) Encrypt(data []byte) ([]byte, error) {
	if enc.chunkSize > 0 {
		return nil, fmt.Errorf("encrypted in stream mode")
	}

	return gmcEncrypt(data, enc.aesKey, enc.baseNonce[:], nil)
}

// Decrypt decrypts the data using the receiver private key and the share data key and returns the plain text.
func (d *Decryptor) Decrypt(cipherText []byte) ([]byte, error) {
	if d.chunkSize > 0 {
		return nil, fmt.Errorf("encrypted in stream mode")
	}

	return gcmDecrypt(cipherText, d.aesKey, d.baseNonce[:], nil)
}

func (d *Decryptor) DecryptByOwner(cipherText []byte) ([]byte, error) {
	if d.chunkSize > 0 {
		return nil, fmt.Errorf("encrypted in stream mode")
	}

	return gcmDecrypt(cipherText, d.aesKey, d.baseNonce[:], nil)
}
