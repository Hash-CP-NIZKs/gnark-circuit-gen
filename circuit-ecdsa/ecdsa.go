package circuit_ecdsa

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/ecdsa"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bls12-377"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/consensys/gnark/std/rangecheck/varuna"
	"github.com/consensys/gnark/std/utils/export_utils"
)

// Signature represents the signature for some message.
type Signature[Scalar emulated.FieldParams] struct {
	R, S emulated.Element[Scalar]
}

// PublicKey represents the public key to verify the signature for.
type PublicKey[Base, Scalar emulated.FieldParams] sw_emulated.AffinePoint[Base]

// Verify asserts that the signature sig verifies for the message msg and public
// key pk. The curve parameters params define the elliptic curve.
//
// We assume that the message msg is already hashed to the scalar field.
func (pk PublicKey[T, S]) Verify(api frontend.API, params sw_emulated.CurveParams, msg *emulated.Element[S], sig *Signature[S]) {
	cr, err := sw_emulated.New[T, S](api, params)
	if err != nil {
		// TODO: softer handling.
		panic(err)
	}
	scalarApi, err := emulated.NewField[S](api)
	if err != nil {
		panic(err)
	}
	baseApi, err := emulated.NewField[T](api)
	if err != nil {
		panic(err)
	}
	pkpt := sw_emulated.AffinePoint[T](pk)
	sInv := scalarApi.Inverse(&sig.S)
	msInv := scalarApi.MulMod(msg, sInv)
	rsInv := scalarApi.MulMod(&sig.R, sInv)

	// q = [rsInv]pkpt + [msInv]g
	q := cr.JointScalarMulBase(&pkpt, rsInv, msInv)
	qx := baseApi.Reduce(&q.X)
	qxBits := baseApi.ToBits(qx)
	rbits := scalarApi.ToBits(&sig.R)
	if len(rbits) != len(qxBits) {
		panic("non-equal lengths")
	}
	for i := range rbits {
		// api.Println(rbits[i], qxBits[i])
		api.AssertIsEqual(rbits[i], qxBits[i])
	}
}

type EcdsaCircuit[T, S emulated.FieldParams] struct {
	Sig Signature[S]
	Msg emulated.Element[S]
	Pub PublicKey[T, S]
}

func (c *EcdsaCircuit[T, S]) Define(api frontend.API) error {
	checker := rangecheck.New(api)
	fmt.Printf("type of rangechecker: %T\n", checker)
	c.Pub.Verify(api, sw_emulated.GetCurveParams[T](), &c.Msg, &c.Sig)
	return nil
}

func RunECDSA() {
	var err error

	// generate parameters
	privKey, _ := ecdsa.GenerateKey(rand.Reader)
	publicKey := privKey.PublicKey

	// sign
	msg := []byte("testing ECDSA (pre-hashed)")
	sigBin, _ := privKey.Sign(msg, nil)

	// check that the signature is correct
	flag, _ := publicKey.Verify(sigBin, msg, nil)
	if !flag {
		panic("can't verify signature")
	}

	// unmarshal signature
	var sig ecdsa.Signature
	sig.SetBytes(sigBin)
	r, s := new(big.Int), new(big.Int)
	r.SetBytes(sig.R[:32])
	s.SetBytes(sig.S[:32])

	hash := ecdsa.HashToInt(msg)

	circuit := EcdsaCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{}
	assignment := EcdsaCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		Sig: Signature[emulated.Secp256k1Fr]{
			R: emulated.ValueOf[emulated.Secp256k1Fr](r),
			S: emulated.ValueOf[emulated.Secp256k1Fr](s),
		},
		Msg: emulated.ValueOf[emulated.Secp256k1Fr](hash),
		Pub: PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](privKey.PublicKey.A.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](privKey.PublicKey.A.Y),
		},
	}

	newBuilder := r1cs.NewBuilder
	var builder frontend.Builder = nil
	var newBuilderWrapper = func(a *big.Int, b frontend.CompileConfig) (c frontend.Builder, d error) {
		c, d = newBuilder(a, b)
		builder = c
		return
	}

	r1cs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), newBuilderWrapper, &circuit)
	if err != nil {
		fmt.Println("error in building circuit", err)
		os.Exit(1)
	}

	println("r1cs.GetNbCoefficients(): ", r1cs.GetNbCoefficients())
	println("r1cs.GetNbConstraints(): ", r1cs.GetNbConstraints())
	println("r1cs.GetNbSecretVariables(): ", r1cs.GetNbSecretVariables())
	println("r1cs.GetNbPublicVariables(): ", r1cs.GetNbPublicVariables())
	println("r1cs.GetNbInternalVariables(): ", r1cs.GetNbInternalVariables())

	fmt.Println("Generating witness", time.Now())
	witness, err := frontend.NewWitness(&assignment, ecc.BLS12_377.ScalarField())
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println("Running Solver", time.Now())
	_solution, err := r1cs.Solve(witness)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	solution := _solution.(*cs.R1CSSolution)
	fmt.Println("solution.W.Len()", solution.W.Len())

	{
		r1cs := r1cs.(constraint.R1CS)

		/* r1cs.cbor */
		err = export_utils.SerializeR1CS(r1cs, "output/r1cs.cbor")
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		/* assignment.cbor */
		err = export_utils.SerializeAssignment(solution, "output/assignment.cbor")
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		/* lookup.cbor */
		lookup := varuna.GetLookupByBuilder(builder)
		err = export_utils.SerializeLookup(lookup, r1cs, "output/lookup.cbor")
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}
}
