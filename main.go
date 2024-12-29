package main

import (
	"gnark-circuit-gen/pkg/circuit_gen"
	"os"

	"github.com/consensys/gnark/logger"
	"github.com/urfave/cli"
)

func handler(test_case circuit_gen.TestCase) func(ctx *cli.Context) error {
	return func(ctx *cli.Context) error {
		return circuit_gen.Run(test_case)
	}
}

func main() {
	log := logger.Logger().With().Logger()

	cliApp := cli.NewApp()
	cliApp.Name = "gnark-circuit-gen"
	cliApp.Usage = "cli to generate circuit required by testing"
	cliApp.Version = "0.0.1"

	cliApp.Commands = []cli.Command{
		cli.Command{
			Name:   "test1",
			Usage:  "generate for test 1",
			Flags:  []cli.Flag{},
			Action: handler(circuit_gen.Test1),
		},
		cli.Command{
			Name:   "test2",
			Usage:  "generate for test 2",
			Flags:  []cli.Flag{},
			Action: handler(circuit_gen.Test2),
		},
		cli.Command{
			Name:   "test3",
			Usage:  "generate for test 3",
			Flags:  []cli.Flag{},
			Action: handler(circuit_gen.Test3),
		},
	}

	err := cliApp.Run(os.Args)
	if err != nil {
		log.Error().Msgf("demo-cli execute error: %v\n", err)
		os.Exit(-1)
	}
}
