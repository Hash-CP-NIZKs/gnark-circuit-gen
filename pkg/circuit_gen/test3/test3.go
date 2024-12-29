package test3

import (
	"fmt"
	"gnark-circuit-gen/common/poseidon"
	"gnark-circuit-gen/pkg/utils"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/rangecheck"
)

type Test3Circuit[Field1, Field2 emulated.FieldParams] struct {
	A1, B1 emulated.Element[Field1] `gnark:",public"`
	A2, B2 emulated.Element[Field2] `gnark:",public"`
	N1, N2 frontend.Variable        `gnark:",public"`
}

type thirtyTwoLimbPrimeField struct{}

func (thirtyTwoLimbPrimeField) NbLimbs() uint     { return 32 }
func (thirtyTwoLimbPrimeField) BitsPerLimb() uint { return 64 }
func (thirtyTwoLimbPrimeField) IsPrime() bool     { return true }

type fourLimbPrimeField struct{}

func (fourLimbPrimeField) NbLimbs() uint     { return 4 }
func (fourLimbPrimeField) BitsPerLimb() uint { return 64 }
func (fourLimbPrimeField) IsPrime() bool     { return true }

// NextPrime[2^2047, 1]
// https://www.wolframalpha.com/input?i=NextPrime%5B2%5E2047%2C+1%5D
var PRIME_FIELD_1_MODULES_OCT_STRING string = "16158503035655503650357438344334975980222051334857742016065172713762327569433945446598600705761456731844358980460949009747059779575245460547544076193224141560315438683650498045875098875194826053398028819192033784138396109321309878080919047169238085235290822926018152521443787945770532904303776199561965192760957166694834171210342487393282284747428088017663161029038902829665513096354230157075129296432088558362971801859230928678799175576150822952201848806616643615613562842355410104862578550863465661734839271290328348967522998634176499319107762583194718667771801067716614802322659239302476074096777926805529798117247"

// NextPrime[2^255, 1]
// https://www.wolframalpha.com/input?i=NextPrime%5B2%5E2047%2C+1%5D
var PRIME_FIELD_2_MODULES_OCT_STRING string = "57896044618658097711785492504343953926634992332820282019728792003956564820063"

var PRIME_FIELD_1_MODULES big.Int
var PRIME_FIELD_2_MODULES big.Int

func init() {
	if _, ok := PRIME_FIELD_1_MODULES.SetString(PRIME_FIELD_1_MODULES_OCT_STRING, 10); !ok {
		panic("invalid modulus " + PRIME_FIELD_1_MODULES_OCT_STRING)
	}

	if _, ok := PRIME_FIELD_2_MODULES.SetString(PRIME_FIELD_2_MODULES_OCT_STRING, 10); !ok {
		panic("invalid modulus " + PRIME_FIELD_2_MODULES_OCT_STRING)
	}
}

type PrimeField2048Bit struct{ thirtyTwoLimbPrimeField }
type PrimeField256Bit struct{ fourLimbPrimeField }

func (fp PrimeField2048Bit) Modulus() *big.Int {
	return new(big.Int).Set(&PRIME_FIELD_1_MODULES)
}
func (fp PrimeField256Bit) Modulus() *big.Int {
	return new(big.Int).Set(&PRIME_FIELD_2_MODULES)
}

func RandomCircuit() (circuit frontend.Circuit, assignment frontend.Circuit, err error) {
	log := logger.Logger().With().Logger()

	log.Info().Msg("generating random values")

	A1, err := utils.RandFieldElement(&PRIME_FIELD_1_MODULES)
	if err != nil {
		return
	}
	B1, err := utils.RandFieldElement(&PRIME_FIELD_1_MODULES)
	if err != nil {
		return
	}

	A2, err := utils.RandFieldElement(&PRIME_FIELD_2_MODULES)
	if err != nil {
		return
	}
	B2, err := utils.RandFieldElement(&PRIME_FIELD_2_MODULES)
	if err != nil {
		return
	}

	N1, err := utils.Rand128Bit()
	if err != nil {
		return
	}

	N2, err := utils.Rand128Bit()
	if err != nil {
		return
	}

	log.Info().Msg("constructing circuit")

	circuit = &Test3Circuit[PrimeField2048Bit, PrimeField256Bit]{}
	assignment = &Test3Circuit[PrimeField2048Bit, PrimeField256Bit]{
		emulated.ValueOf[PrimeField2048Bit](A1),
		emulated.ValueOf[PrimeField2048Bit](B1),
		emulated.ValueOf[PrimeField256Bit](A2),
		emulated.ValueOf[PrimeField256Bit](B2),
		N1,
		N2,
	}

	return
}

func (c *Test3Circuit[Field1, Field2]) Define(api frontend.API) error {
	log := logger.Logger().With().Logger()
	checker := rangecheck.New(api)

	log.Debug().Msg(fmt.Sprintf("using range checker: %T", checker))

	log.Info().Msg("build circuit now")

	/*
	 * Hash 1
	 */
	{
		hash_chip := poseidon.NewBLS12377Chip(api)
		hash_values := []frontend.Variable{}

		hash_values = append(hash_values, c.A1.Limbs...)
		hash_values = append(hash_values, c.A2.Limbs...)
		hash_values = append(hash_values, c.N1)

		hash_chip.HashNoPad(hash_values)

	}
	/*
	 * Hash 2
	 */
	{
		hash_chip := poseidon.NewBLS12377Chip(api)
		hash_values := []frontend.Variable{}

		hash_values = append(hash_values, c.B1.Limbs...)
		hash_values = append(hash_values, c.B2.Limbs...)
		hash_values = append(hash_values, c.N2)

		hash_chip.HashNoPad(hash_values)
	}

	/*
	 * Non native Mul
	 */
	{
		scalarApi, err := emulated.NewField[Field1](api)
		if err != nil {
			return err
		}
		scalarApi.Mul(&c.A1, &c.B1)
	}

	/*
	 * Non native Mul
	 */
	{
		scalarApi, err := emulated.NewField[Field2](api)
		if err != nil {
			return err
		}
		scalarApi.Mul(&c.A2, &c.B2)
	}
	return nil
}
