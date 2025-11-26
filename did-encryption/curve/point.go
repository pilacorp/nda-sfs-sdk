package curve

import (
	"crypto/ecdsa"
	"math/big"

	crypt "github.com/ethereum/go-ethereum/crypto"
)

var CURVE = crypt.S256()
var P = CURVE.Params().P
var N = CURVE.Params().N

type CurvePoint = ecdsa.PublicKey

func PointScalarAdd(a, b *CurvePoint) *CurvePoint {
	x, y := CURVE.Add(a.X, a.Y, b.X, b.Y)
	return &CurvePoint{CURVE, x, y}
}

func PointScalarMul(a *CurvePoint, k *big.Int) *CurvePoint {
	x, y := a.ScalarMult(a.X, a.Y, k.Bytes())
	return &CurvePoint{CURVE, x, y}
}

func BigIntMulBase(k *big.Int) *CurvePoint {
	x, y := CURVE.ScalarBaseMult(k.Bytes())
	return &CurvePoint{CURVE, x, y}
}

func PointToBytes(point *ecdsa.PublicKey) (res []byte) {
	return crypt.FromECDSAPub(point)
}

func BytesToPublicKey(bytes []byte) (*ecdsa.PublicKey, error) {
	return crypt.UnmarshalPubkey(bytes)
}
