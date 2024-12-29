package utils

import (
	"crypto/rand"
	"io"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/ecdsa"
)

func RandP256G() (secp256k1.G1Affine, error) {
	privKey, err := ecdsa.GenerateKey(rand.Reader)
	return privKey.PublicKey.A, err
}

func RandFieldElement(modulus *big.Int) (k *big.Int, err error) {
	b := make([]byte, modulus.BitLen()/8+8)
	_, err = io.ReadFull(rand.Reader, b)
	if err != nil {
		return
	}

	one := new(big.Int).SetInt64(1)

	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(modulus, one)
	k.Mod(k, n)
	k.Add(k, one)

	return
}

func Rand128Bit() (*big.Int, error) {
	res := new(big.Int)

	b := make([]byte, 128/8)
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		return res, err
	}

	res.SetBytes(b)

	return res, nil
}
