package circuit_ecdsa

import (
	"crypto/rand"
	"flag"
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

func CreateCircuitAndAssignment() (EcdsaCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr], EcdsaCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]) {
	pkXStr := flag.String("pk_x", "", "The pk_x large integer in base-10")
	pkYStr := flag.String("pk_y", "", "The pk_y large integer in base-10")
	sigRStr := flag.String("sig_r", "", "The sig_r large integer in base-10")
	sigSStr := flag.String("sig_s", "", "The sig_s large integer in base-10")
	hashStr := flag.String("hash", "", "The hash large integer in base-10")

	flag.Parse()

	if *pkXStr == "" && *pkYStr == "" && *sigRStr == "" && *sigSStr == "" && *hashStr == "" {
		fmt.Println("No parameters were specified. Generate parameters now")

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
		return circuit, assignment
	} else if *pkXStr != "" && *pkYStr != "" && *sigRStr != "" && *sigSStr != "" && *hashStr != "" {
		pkX, ok := new(big.Int).SetString(*pkXStr, 10)
		if !ok {
			fmt.Println("Invalid pk_x value")
			os.Exit(1)
		}

		pkY, ok := new(big.Int).SetString(*pkYStr, 10)
		if !ok {
			fmt.Println("Invalid pk_y value")
			os.Exit(1)
		}

		sigR, ok := new(big.Int).SetString(*sigRStr, 10)
		if !ok {
			fmt.Println("Invalid sig_r value")
			os.Exit(1)
		}

		sigS, ok := new(big.Int).SetString(*sigSStr, 10)
		if !ok {
			fmt.Println("Invalid sig_s value")
			os.Exit(1)
		}

		hash, ok := new(big.Int).SetString(*hashStr, 10)
		if !ok {
			fmt.Println("Invalid hash value")
			os.Exit(1)
		}

		// var publicKey ecdsa.PublicKey
		// publicKey.A.X.SetBigInt(pkX)
		// publicKey.A.Y.SetBigInt(pkY)

		var publicKey ecdsa.PublicKey
		err := publicKey.A.X.SetBytesCanonical(pkX.Bytes())
		if err != nil {
			panic("publicKey.A.X failed")
		}
		err = publicKey.A.Y.SetBytesCanonical(pkY.Bytes())
		if err != nil {
			panic("publicKey.A.Y failed")
		}

		var sig ecdsa.Signature
		var t [64]byte
		sigR.FillBytes(t[:32])
		sigS.FillBytes(t[32:])
		_, err = sig.SetBytes(t[:])
		if err != nil {
			panic("sig.SetBytes failed")
		}

		flag, err := publicKey.Verify(sig.Bytes(), hash.Bytes(), nil)
		if !flag {
			panic("can't verify signature")
		} else if err != nil {
			panic("can't verify signature, err not nil")
		} else {
			println("verify is ok")
		}

		circuit := EcdsaCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{}
		assignment := EcdsaCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			Sig: Signature[emulated.Secp256k1Fr]{
				R: emulated.ValueOf[emulated.Secp256k1Fr](sigR),
				S: emulated.ValueOf[emulated.Secp256k1Fr](sigS),
			},
			Msg: emulated.ValueOf[emulated.Secp256k1Fr](hash),
			Pub: PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
				X: emulated.ValueOf[emulated.Secp256k1Fp](pkX),
				Y: emulated.ValueOf[emulated.Secp256k1Fp](pkY),
			},
		}
		return circuit, assignment
	} else {
		fmt.Println("Invalid parameters !!!!")
		if *pkXStr == "" {
			fmt.Println("pk_x is empty!!!")
		}
		if *pkYStr == "" {
			fmt.Println("pk_y is empty!!!")
		}
		if *sigRStr == "" {
			fmt.Println("sig_r is empty!!!")
		}
		if *sigSStr == "" {
			fmt.Println("sig_s is empty!!!")
		}
		if *hashStr == "" {
			fmt.Println("hash is empty!!!")
		}
		panic("Invalid parameters so we exit now")
	}
}

func RunECDSA() {
	var err error

	circuit, assignment := CreateCircuitAndAssignment()

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
