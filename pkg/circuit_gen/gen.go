package circuit_gen

import (
	"gnark-circuit-gen/pkg/circuit_gen/test1"
	"gnark-circuit-gen/pkg/circuit_gen/test2"
	"gnark-circuit-gen/pkg/circuit_gen/test3"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bls12-377"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/std/rangecheck/varuna"
	"github.com/consensys/gnark/std/utils/export_utils"
)

type TestCase uint32

const (
	Test1 TestCase = 1
	Test2 TestCase = 2
	Test3 TestCase = 3
)

func Run(testCase TestCase) (err error) {

	var circuit, assignment frontend.Circuit = nil, nil
	switch {
	case testCase == Test1:
		circuit, assignment, err = test1.RandomCircuit()
	case testCase == Test2:
		circuit, assignment, err = test2.RandomCircuit()
	case testCase == Test3:
		circuit, assignment, err = test3.RandomCircuit()
	default:
		panic("Unknown TestCase")
	}

	if err != nil {
		return
	}
	err = genForCircuit(circuit, assignment)
	if err != nil {
		return
	}

	return nil
}

func genForCircuit(circuit frontend.Circuit, assignment frontend.Circuit) error {
	log := logger.Logger().With().Logger()

	newBuilder := r1cs.NewBuilder
	var builder frontend.Builder = nil
	var newBuilderWrapper = func(a *big.Int, b frontend.CompileConfig) (c frontend.Builder, d error) {
		c, d = newBuilder(a, b)
		builder = c
		return
	}

	r1cs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), newBuilderWrapper, circuit)
	if err != nil {
		log.Error().Msgf("error in building circuit: %s", err)
		return err
	}

	log.Info().Msg("running gnark solver to generate solution (assignment)")
	witness, err := frontend.NewWitness(assignment, ecc.BLS12_377.ScalarField())
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
