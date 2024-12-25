package circuit_test1

import (
	"fmt"
	"gnark-circuit-gen/common/poseidon"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/rangecheck"
)

type Test1Circuit[Base, Scalar emulated.FieldParams] struct {
	G1, G2 sw_emulated.AffinePoint[Base] `gnark:",public"`
	S1, S2 emulated.Element[Scalar]      `gnark:",public"`
	N1, N2 frontend.Variable             `gnark:",public"`
}

func (c *Test1Circuit[Base, Scalar]) Define(api frontend.API) error {
	log := logger.Logger().With().Logger()
	checker := rangecheck.New(api)

	log.Info().Msg(fmt.Sprintf("using range checker: %T", checker))

	log.Info().Msg("build circuit now")

	/*
	 * Hash 1
	 */
	{
		hash_chip := poseidon.NewBLS12377Chip(api)
		hash_values := []frontend.Variable{}

		hash_values = append(hash_values, c.G1.X.Limbs...)
		hash_values = append(hash_values, c.G1.Y.Limbs...)

		hash_values = append(hash_values, c.S1.Limbs...)

		hash_values = append(hash_values, c.N1)

		hash_chip.HashNoPad(hash_values)

	}
	/*
	 * Hash 2
	 */
	{
		hash_chip := poseidon.NewBLS12377Chip(api)
		hash_values := []frontend.Variable{}

		hash_values = append(hash_values, c.G2.X.Limbs...)
		hash_values = append(hash_values, c.G2.Y.Limbs...)

		hash_values = append(hash_values, c.S2.Limbs...)

		hash_values = append(hash_values, c.N2)

		hash_chip.HashNoPad(hash_values)
	}

	/*
	 * Non native Add
	 */
	scalarApi, err := emulated.NewField[Scalar](api)
	if err != nil {
		return err
	}
	scalarApi.Add(&c.S1, &c.S2)

	/*
	 * Add op for two AffinePoint
	 * See: https://github.com/Consensys/gnark/blob/e1cb5a703defd33473e7481f8b4af9ffde7230ec/std/algebra/emulated/sw_emulated/point.go#L108
	 */
	baseApi, err := emulated.NewField[Base](api)
	if err != nil {
		return err
	}
	p := &c.G1
	q := &c.G2
	// compute λ = (q.y-p.y)/(q.x-p.x)
	qypy := baseApi.Sub(&q.Y, &p.Y)
	qxpx := baseApi.Sub(&q.X, &p.X)
	λ := baseApi.Div(qypy, qxpx)

	// xr = λ²-p.x-q.x
	λλ := baseApi.MulMod(λ, λ)
	qxpx = baseApi.Add(&p.X, &q.X)
	xr := baseApi.Sub(λλ, qxpx)

	// p.y = λ(p.x-r.x) - p.y
	pxrx := baseApi.Sub(&p.X, xr)
	λpxrx := baseApi.MulMod(λ, pxrx)
	yr := baseApi.Sub(λpxrx, &p.Y)

	_ = &sw_emulated.AffinePoint[Base]{
		X: *baseApi.Reduce(xr),
		Y: *baseApi.Reduce(yr),
	}
	return nil
}
