package circuit_test1

import (
	"crypto/rand"
	"io"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/ecdsa"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bls12-377"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/rangecheck/varuna"
	"github.com/consensys/gnark/std/utils/export_utils"
)

func RandG() (secp256k1.G1Affine, error) {
	privKey, err := ecdsa.GenerateKey(rand.Reader)
	return privKey.PublicKey.A, err
}

func RandScalarFieldElement() (k *big.Int, err error) {
	b := make([]byte, fr.Bits/8+8)
	_, err = io.ReadFull(rand.Reader, b)
	if err != nil {
		return
	}

	one := new(big.Int).SetInt64(1)

	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(fr.Modulus(), one)
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

func Run() error {
	var err error

	log := logger.Logger().With().Logger()

	log.Info().Msg("generating random values")

	G1, err := RandG()
	if err != nil {
		return err
	}
	G2, err := RandG()
	if err != nil {
		return err
	}

	S1, err := RandScalarFieldElement()
	if err != nil {
		return err
	}
	S2, err := RandScalarFieldElement()
	if err != nil {
		return err
	}

	N1, err := Rand128Bit()
	if err != nil {
		return err
	}

	N2, err := Rand128Bit()
	if err != nil {
		return err
	}

	log.Info().Msg("constructing circuit")

	circuit := Test1Circuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{}
	assignment := Test1Circuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](G1.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](G1.Y),
		},
		sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](G2.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](G2.Y),
		},
		emulated.ValueOf[emulated.Secp256k1Fr](S1),
		emulated.ValueOf[emulated.Secp256k1Fr](S2),
		N1,
		N2,
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
		log.Error().Msgf("error in building circuit: %s", err)
		return err
	}

	log.Info().Msg("running gnark solver to generate solution (assignment)")
	witness, err := frontend.NewWitness(&assignment, ecc.BLS12_377.ScalarField())
	if err != nil {
		return err
	}
	_solution, err := r1cs.Solve(witness)
	if err != nil {
		return err
	}
	solution := _solution.(*cs.R1CSSolution)

	log.Info().Msgf("---------- [start] r1cs info   ----------")

	log.Info().Msgf("r1cs.GetNbCoefficients(): %d", r1cs.GetNbCoefficients())
	log.Info().Msgf("r1cs.GetNbConstraints(): %d", r1cs.GetNbConstraints())
	log.Info().Msgf("r1cs.GetNbSecretVariables(): %d", r1cs.GetNbSecretVariables())
	log.Info().Msgf("r1cs.GetNbPublicVariables(): %d", r1cs.GetNbPublicVariables())
	log.Info().Msgf("r1cs.GetNbInternalVariables(): %d", r1cs.GetNbInternalVariables())
	log.Info().Msgf("solution.W.Len(): %d", solution.W.Len())
	log.Info().Msgf("---------- [ end ] r1cs info   ----------")

	{
		log.Info().Msgf("---------- [start] export r1cs ----------")
		r1cs := r1cs.(constraint.R1CS)

		/* r1cs.cbor */
		err = export_utils.SerializeR1CS(r1cs, "output/r1cs.cbor")
		if err != nil {
			return err
		}

		/* assignment.cbor */
		err = export_utils.SerializeAssignment(r1cs, solution, "output/assignment.cbor")
		if err != nil {
			return err
		}

		/* lookup.cbor */
		lookup := varuna.GetLookupByBuilder(builder)
		err = export_utils.SerializeLookup(lookup, r1cs, "output/lookup.cbor")
		if err != nil {
			return err
		}
		log.Info().Msgf("---------- [ end ] export r1cs ----------")
	}
	return nil
}
