package poseidon

// This is a customized implementation of the Poseidon hash function inside the BLS12377 field.
// This implementation is based on the following implementation:
//
// 		https://github.com/iden3/go-iden3-crypto/blob/master/poseidon/poseidon.go
//
// The input and output are modified to ingest Goldilocks field elements.

import (
	"math/big"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark/frontend"
)

const BLS12377_SPONGE_WIDTH int = 4
const BLS12377_SPONGE_RATE int = 3

type BLS12377Chip struct {
	api frontend.API `gnark:"-"`
}

type BLS12377State = [BLS12377_SPONGE_WIDTH]frontend.Variable
type BLS12377HashOut = frontend.Variable

func NewBLS12377Chip(api frontend.API) *BLS12377Chip {
	if api.Compiler().Field().Cmp(bls12377.ID.ScalarField()) != 0 {
		panic("Gnark compiler not set to BLS12377 scalar field")
	}

	return &BLS12377Chip{api: api}
}

func (c *BLS12377Chip) Poseidon(state BLS12377State) BLS12377State {
	state = c.ark(state, 0)
	state = c.fullRounds(state, true)
	state = c.partialRounds(state)
	state = c.fullRounds(state, false)
	return state
}

func (c *BLS12377Chip) HashNoPad(input []frontend.Variable) BLS12377HashOut {
	state := BLS12377State{
		frontend.Variable(0),
		frontend.Variable(0),
		frontend.Variable(0),
		frontend.Variable(0),
	}

	two_to_32 := new(big.Int).SetInt64(1 << 32)
	two_to_64 := new(big.Int).Mul(two_to_32, two_to_32)

	for i := 0; i < len(input); i += BLS12377_SPONGE_RATE * 3 {
		endI := c.min(len(input), i+BLS12377_SPONGE_RATE*3)
		rateChunk := input[i:endI]
		for j, stateIdx := 0, 0; j < len(rateChunk); j, stateIdx = j+3, stateIdx+1 {
			endJ := c.min(len(rateChunk), j+3)
			chunk := rateChunk[j:endJ]

			inter := frontend.Variable(0)
			for k := 0; k < len(chunk); k++ {
				inter = c.api.MulAcc(inter, chunk[k], new(big.Int).Exp(two_to_64, big.NewInt(int64(k)), nil))
			}

			state[stateIdx+1] = inter
		}

		state = c.Poseidon(state)
	}

	return BLS12377HashOut(state[0])
}

func (c *BLS12377Chip) HashOrNoop(input []frontend.Variable) BLS12377HashOut {
	if len(input) <= 3 {
		returnVal := frontend.Variable(0)

		alpha := new(big.Int).SetInt64(1 << 32)
		alpha = new(big.Int).Mul(alpha, alpha)
		for i, inputElement := range input {
			mulFactor := new(big.Int).Exp(alpha, big.NewInt(int64(i)), nil)
			returnVal = c.api.MulAcc(returnVal, inputElement, mulFactor)
		}

		return BLS12377HashOut(returnVal)
	} else {
		return c.HashNoPad(input)
	}
}

func (c *BLS12377Chip) TwoToOne(left BLS12377HashOut, right BLS12377HashOut) BLS12377HashOut {
	var inputs BLS12377State
	inputs[0] = frontend.Variable(0)
	inputs[1] = frontend.Variable(0)
	inputs[2] = left
	inputs[3] = right
	state := c.Poseidon(inputs)
	return state[0]
}

func (c *BLS12377Chip) ToVec(hash BLS12377HashOut) []frontend.Variable {
	bits := c.api.ToBinary(hash)

	returnElements := []frontend.Variable{}

	// Split into 7 byte chunks, since 8 byte chunks can result in collisions
	chunkSize := 56
	for i := 0; i < len(bits); i += chunkSize {
		maxIdx := c.min(len(bits), i+chunkSize)
		bitChunk := bits[i:maxIdx]
		returnElements = append(returnElements, frontend.Variable(c.api.FromBinary(bitChunk...)))
	}

	return returnElements
}

func (c *BLS12377Chip) min(x, y int) int {
	if x < y {
		return x
	}

	return y
}

func (c *BLS12377Chip) fullRounds(state BLS12377State, isFirst bool) BLS12377State {
	for i := 0; i < BLS12377_FULL_ROUNDS/2-1; i++ {
		state = c.exp5state(state)
		if isFirst {
			state = c.ark(state, (i+1)*BLS12377_SPONGE_WIDTH)
		} else {
			state = c.ark(state, (BLS12377_FULL_ROUNDS/2+1)*BLS12377_SPONGE_WIDTH+BLS12377_PARTIAL_ROUNDS+i*BLS12377_SPONGE_WIDTH)
		}
		state = c.mix(state, mMatrixBLS12377)
	}

	state = c.exp5state(state)
	if isFirst {
		state = c.ark(state, (BLS12377_FULL_ROUNDS/2)*BLS12377_SPONGE_WIDTH)
		state = c.mix(state, pMatrixBLS12377)
	} else {
		state = c.mix(state, mMatrixBLS12377)
	}

	return state
}

func (c *BLS12377Chip) partialRounds(state BLS12377State) BLS12377State {
	for i := 0; i < BLS12377_PARTIAL_ROUNDS; i++ {
		state[0] = c.exp5(state[0])
		state[0] = c.api.Add(state[0], cConstantsBLS12377[(BLS12377_FULL_ROUNDS/2+1)*BLS12377_SPONGE_WIDTH+i])

		newState0 := frontend.Variable(0)
		for j := 0; j < BLS12377_SPONGE_WIDTH; j++ {
			newState0 = c.api.MulAcc(newState0, sConstantsBLS12377[(BLS12377_SPONGE_WIDTH*2-1)*i+j], state[j])
		}

		for k := 1; k < BLS12377_SPONGE_WIDTH; k++ {
			state[k] = c.api.MulAcc(state[k], state[0], sConstantsBLS12377[(BLS12377_SPONGE_WIDTH*2-1)*i+BLS12377_SPONGE_WIDTH+k-1])
		}
		state[0] = newState0
	}

	return state
}

func (c *BLS12377Chip) ark(state BLS12377State, it int) BLS12377State {
	var result BLS12377State

	for i := 0; i < len(state); i++ {
		result[i] = c.api.Add(state[i], cConstantsBLS12377[it+i])
	}

	return result
}

func (c *BLS12377Chip) exp5(x frontend.Variable) frontend.Variable {
	x2 := c.api.Mul(x, x)
	x4 := c.api.Mul(x2, x2)
	return c.api.Mul(x4, x)
}

func (c *BLS12377Chip) exp5state(state BLS12377State) BLS12377State {
	for i := 0; i < BLS12377_SPONGE_WIDTH; i++ {
		state[i] = c.exp5(state[i])
	}
	return state
}

func (c *BLS12377Chip) mix(state_ BLS12377State, constantMatrix [][]*big.Int) BLS12377State {
	var result BLS12377State

	for i := 0; i < BLS12377_SPONGE_WIDTH; i++ {
		result[i] = frontend.Variable(0)
	}

	for i := 0; i < BLS12377_SPONGE_WIDTH; i++ {
		for j := 0; j < BLS12377_SPONGE_WIDTH; j++ {
			result[i] = c.api.MulAcc(result[i], constantMatrix[j][i], state_[j])
		}
	}

	return result
}
