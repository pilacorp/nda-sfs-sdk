package didencrypt

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"

	crypt "github.com/ethereum/go-ethereum/crypto"
	"github.com/pilacorp/did-encryption/curve"
	"github.com/pilacorp/did-encryption/utils"
)

type Encryptor struct {
	aesKey    [32]byte
	baseNonce [12]byte
	chunkSize uint32
}

type Decryptor struct {
	aesKey    [32]byte
	baseNonce [12]byte
	chunkSize uint32
}

type capsule struct {
	E         *ecdsa.PublicKey
	V         *ecdsa.PublicKey
	S         *big.Int
	ChunkSize uint32
	Version   uint8
}

func (d *Decryptor) Hex() (string, error) {
	buf := new(bytes.Buffer)
	order := binary.LittleEndian

	if err := binary.Write(buf, order, d.aesKey); err != nil {
		return "", err
	}
	if err := binary.Write(buf, order, d.baseNonce); err != nil {
		return "", err
	}
	if err := binary.Write(buf, order, d.chunkSize); err != nil {
		return "", err
	}

	return hex.EncodeToString(buf.Bytes()), nil
}

func NewDecryptorFromHex(hexString string) (*Decryptor, error) {
	binaryData, err := hex.DecodeString(hexString)
	if err != nil {
		return nil, err
	}

	buf := bytes.NewReader(binaryData)
	var d Decryptor
	order := binary.LittleEndian

	if err := binary.Read(buf, order, &d.aesKey); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, order, &d.baseNonce); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, order, &d.chunkSize); err != nil {
		return nil, err
	}

	return &d, nil
}

func NewEncryptor(pubKey string, chunkSize uint32) (*Encryptor, []byte, error) {
	pKey, err := utils.PublicCompressedKeyToKey(pubKey)
	if err != nil {
		return nil, nil, err
	}

	capObj, keyBytes, err := generateAESKey(pKey, uint32(chunkSize))
	if err != nil {
		return nil, nil, err
	}

	capsuleBytes, err := encodeCapsule(capObj)
	if err != nil {
		return nil, nil, err
	}

	// TODO: derive the aes key and base nonce by HKDF.
	enc := &Encryptor{
		aesKey:    [32]byte(keyBytes[:32]),
		baseNonce: [12]byte(keyBytes[:12]),
		chunkSize: chunkSize,
	}

	return enc, capsuleBytes, nil
}

func NewDecryptor(recieverPrvKey string, reCapsule []byte) (*Decryptor, error) {
	prvKey, err := utils.PrivateKeyStrToKey(recieverPrvKey)
	if err != nil {
		return nil, err
	}

	if len(reCapsule) != 250 {
		return nil, fmt.Errorf("invalid share data key")
	}

	cap, err := decodeCapsule(reCapsule[:185])
	if err != nil {
		return nil, err
	}

	pubX, err := curve.BytesToPublicKey(reCapsule[185:])
	if err != nil {
		return nil, err
	}

	keyBytes, err := decryptAESKey(prvKey, cap, pubX)
	if err != nil {
		return nil, err
	}

	return &Decryptor{
		aesKey:    [32]byte(keyBytes[:32]),
		baseNonce: [12]byte(keyBytes[:12]),
		chunkSize: (cap.ChunkSize),
	}, nil
}

func NewDecryptorByOwner(ownerPrvKey string, capsule []byte) (*Decryptor, error) {
	prvKey, err := utils.PrivateKeyStrToKey(ownerPrvKey)
	if err != nil {
		return nil, err
	}

	if len(capsule) != 185 {
		return nil, fmt.Errorf("invalid original capsule")
	}

	cap, err := decodeCapsule(capsule)
	if err != nil {
		return nil, err
	}

	keyBytes, err := decryptAESKeyByOwner(prvKey, cap)
	if err != nil {
		return nil, err
	}

	return &Decryptor{
		aesKey:    [32]byte(keyBytes[:32]),
		baseNonce: [12]byte(keyBytes[:12]),
		chunkSize: cap.ChunkSize,
	}, nil
}

// CreateReCapsule creates a recapsule from the owner private key and the receiver public key for the receiver.
func CreateReCapsule(ownerPrvKey, recieverPubKey string, capsule []byte) ([]byte, error) {
	prvKey, err := utils.PrivateKeyStrToKey(ownerPrvKey)
	if err != nil {
		return nil, err
	}

	pubKey, err := utils.PublicCompressedKeyToKey(recieverPubKey)
	if err != nil {
		return nil, err
	}

	r, p, err := rekeyGenerate(prvKey, pubKey)
	if err != nil {
		fmt.Println(err)
	}

	cap, err := decodeCapsule(capsule)
	if err != nil {
		return nil, err
	}

	reCap, err := reEncryption(r, cap)
	if err != nil {
		return nil, err
	}

	reCapBytes, err := encodeCapsule(reCap)
	if err != nil {
		return nil, err
	}

	return utils.ConcatBytes(reCapBytes, curve.PointToBytes(p)), nil
}

func encodeRekey(r *big.Int, p *ecdsa.PublicKey) ([]byte, error) {
	buf := new(bytes.Buffer)

	sBytes := r.Bytes()
	if err := binary.Write(buf, binary.LittleEndian, uint32(len(sBytes))); err != nil {
		return nil, err
	}

	if _, err := buf.Write(sBytes); err != nil {
		return nil, err
	}

	pX, pY := p.X.Bytes(), p.Y.Bytes()

	if err := binary.Write(buf, binary.LittleEndian, uint32(len(pX))); err != nil {
		return nil, err
	}

	if _, err := buf.Write(pX); err != nil {
		return nil, err
	}

	if err := binary.Write(buf, binary.LittleEndian, uint32(len(pY))); err != nil {
		return nil, err
	}

	if _, err := buf.Write(pY); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func decodeRekey(data []byte) (*big.Int, *ecdsa.PublicKey, error) {
	rData := bytes.NewReader(data)

	r, err := readBig(rData)
	if err != nil {
		return nil, nil, err
	}

	p := new(ecdsa.PublicKey)
	p.Curve = crypt.S256()

	p.X, err = readBig(rData)
	if err != nil {
		return nil, nil, err
	}

	p.Y, err = readBig(rData)
	if err != nil {
		return nil, nil, err
	}

	return r, p, nil
}

func encodeCapsule(cap *capsule) ([]byte, error) {
	buf := new(bytes.Buffer)

	ecX, ecY := cap.E.X.Bytes(), cap.E.Y.Bytes()

	if err := binary.Write(buf, binary.LittleEndian, uint32(len(ecX))); err != nil {
		return nil, err
	}

	if _, err := buf.Write(ecX); err != nil {
		return nil, err
	}

	if err := binary.Write(buf, binary.LittleEndian, uint32(len(ecY))); err != nil {
		return nil, err
	}

	if _, err := buf.Write(ecY); err != nil {
		return nil, err
	}

	vX, vY := cap.V.X.Bytes(), cap.V.Y.Bytes()

	if err := binary.Write(buf, binary.LittleEndian, uint32(len(vX))); err != nil {
		return nil, err
	}

	if _, err := buf.Write(vX); err != nil {
		return nil, err
	}

	if err := binary.Write(buf, binary.LittleEndian, uint32(len(vY))); err != nil {
		return nil, err
	}

	if _, err := buf.Write(vY); err != nil {
		return nil, err
	}

	sBytes := cap.S.Bytes()
	if err := binary.Write(buf, binary.LittleEndian, uint32(len(sBytes))); err != nil {
		return nil, err
	}

	if _, err := buf.Write(sBytes); err != nil {
		return nil, err
	}

	if err := binary.Write(buf, binary.LittleEndian, cap.ChunkSize); err != nil {
		return nil, err
	}

	if err := binary.Write(buf, binary.LittleEndian, cap.Version); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func decodeCapsule(data []byte) (*capsule, error) {
	r := bytes.NewReader(data)
	c := new(capsule)

	c.E = new(ecdsa.PublicKey)
	c.E.Curve = crypt.S256()
	c.V = new(ecdsa.PublicKey)
	c.V.Curve = crypt.S256()

	var err error

	c.E.X, err = readBig(r)
	if err != nil {
		return nil, err
	}

	c.E.Y, err = readBig(r)
	if err != nil {
		return nil, err
	}

	c.V.X, err = readBig(r)
	if err != nil {
		return nil, err
	}

	c.V.Y, err = readBig(r)
	if err != nil {
		return nil, err
	}

	c.S, err = readBig(r)
	if err != nil {
		return nil, err
	}

	if err := binary.Read(r, binary.LittleEndian, &c.ChunkSize); err != nil {
		return nil, err
	}

	if err := binary.Read(r, binary.LittleEndian, &c.Version); err != nil {
		return nil, err
	}

	return c, nil
}

func readBig(r *bytes.Reader) (*big.Int, error) {
	var l uint32

	if err := binary.Read(r, binary.LittleEndian, &l); err != nil {
		return nil, err
	}

	b := make([]byte, l)
	if _, err := r.Read(b); err != nil {
		return nil, err
	}

	return new(big.Int).SetBytes(b), nil
}

func decryptAESKey(prvKey *ecdsa.PrivateKey, cap *capsule, pointX *ecdsa.PublicKey) (keyBytes []byte, err error) {
	S := curve.PointScalarMul(pointX, prvKey.D)

	d := utils.HashToCurve(
		utils.ConcatBytes(
			utils.ConcatBytes(
				curve.PointToBytes(pointX),
				curve.PointToBytes(&prvKey.PublicKey)),
			curve.PointToBytes(S)))

	point := curve.PointScalarMul(
		curve.PointScalarAdd(cap.E, cap.V), d)

	keyBytes, err = utils.Sha3Hash(curve.PointToBytes(point))
	if err != nil {
		return nil, err
	}

	return keyBytes, nil
}

func decryptAESKeyByOwner(prvKey *ecdsa.PrivateKey, cap *capsule) ([]byte, error) {
	point1 := curve.PointScalarAdd(cap.E, cap.V)
	point := curve.PointScalarMul(point1, prvKey.D)

	return utils.Sha3Hash(curve.PointToBytes(point))
}

func rekeyGenerate(ownerPrvKey *ecdsa.PrivateKey, recieverPubKey *ecdsa.PublicKey) (*big.Int, *ecdsa.PublicKey, error) {
	priX, pubX, err := utils.GenerateKeys()
	if err != nil {
		return nil, nil, err
	}

	point := curve.PointScalarMul(recieverPubKey, priX.D)
	d := utils.HashToCurve(
		utils.ConcatBytes(
			utils.ConcatBytes(
				curve.PointToBytes(pubX),
				curve.PointToBytes(recieverPubKey)),
			curve.PointToBytes(point)))

	rk := curve.BigIntMul(ownerPrvKey.D, curve.GetInvert(d))
	rk.Mod(rk, curve.N)

	return rk, pubX, nil
}

func reEncryption(rk *big.Int, cap *capsule) (*capsule, error) {
	x1, y1 := curve.CURVE.ScalarBaseMult(cap.S.Bytes())
	tempX, tempY := curve.CURVE.ScalarMult(cap.E.X, cap.E.Y,
		utils.HashToCurve(
			utils.ConcatBytes(
				curve.PointToBytes(cap.E),
				curve.PointToBytes(cap.V))).Bytes())
	x2, y2 := curve.CURVE.Add(cap.V.X, cap.V.Y, tempX, tempY)

	if x1.Cmp(x2) != 0 || y1.Cmp(y2) != 0 {
		return nil, fmt.Errorf("%s", "Capsule not match")
	}

	newCapsule := &capsule{
		E:         curve.PointScalarMul(cap.E, rk),
		V:         curve.PointScalarMul(cap.V, rk),
		S:         cap.S,
		ChunkSize: cap.ChunkSize,
		Version:   cap.Version,
	}

	return newCapsule, nil
}

func generateAESKey(pubKey *ecdsa.PublicKey, chunkSize uint32) (cap *capsule, keyBytes []byte, err error) {
	s := new(big.Int)
	priE, pubE, err := utils.GenerateKeys()
	priV, pubV, err := utils.GenerateKeys()
	if err != nil {
		return nil, nil, err
	}

	h := utils.HashToCurve(
		utils.ConcatBytes(
			curve.PointToBytes(pubE),
			curve.PointToBytes(pubV)))

	s = curve.BigIntAdd(priV.D, curve.BigIntMul(priE.D, h))
	point := curve.PointScalarMul(pubKey, curve.BigIntAdd(priE.D, priV.D))

	keyBytes, err = utils.Sha3Hash(curve.PointToBytes(point))
	if err != nil {
		return nil, nil, err
	}

	cap = &capsule{
		E:         pubE,
		V:         pubV,
		S:         s,
		ChunkSize: chunkSize,
	}

	return cap, keyBytes, nil
}

func createRekey(ownerPrvKey *ecdsa.PrivateKey, recieverPubKey *ecdsa.PublicKey) ([]byte, error) {
	r, p, err := rekeyGenerate(ownerPrvKey, recieverPubKey)
	if err != nil {
		fmt.Println(err)
	}

	return encodeRekey(r, p)
}

func reEncrypt(cap []byte, rekeyBytes []byte) ([]byte, error) {
	r, pubX, err := decodeRekey(rekeyBytes)
	if err != nil {
		return nil, err
	}

	decodeCap, err := decodeCapsule(cap)
	if err != nil {
		fmt.Println("decode error:", err)

		return nil, err
	}

	reCap, err := reEncryption(r, decodeCap)
	if err != nil {
		fmt.Println("re encryption error:", err)

		return nil, err
	}

	reCapsuleAsBytes, err := encodeCapsule(reCap)
	if err != nil {
		fmt.Println("encode error:", err)

		return nil, err
	}

	return utils.ConcatBytes(reCapsuleAsBytes, curve.PointToBytes(pubX)), nil
}
