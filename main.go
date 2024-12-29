package main

import (
	circuit_test1 "gnark-circuit-gen/circuit-test1"
	"os"

	"github.com/rs/zerolog/log"
	"github.com/urfave/cli"
)

func main() {
	cliApp := cli.NewApp()
	cliApp.Name = "gnark-circuit-gen"
	cliApp.Usage = "cli to generate circuit required by testing"
	cliApp.Version = "0.0.1"

	cliApp.Commands = []cli.Command{
		cli.Command{
			Name:  "test1",
			Usage: "generate for test 1",
			Flags: []cli.Flag{},
			Action: func(ctx *cli.Context) error {
				return circuit_test1.Run()
			},
		},
		cli.Command{
			Name:  "test2",
			Usage: "generate for test 2",
			Flags: []cli.Flag{},
			Action: func(ctx *cli.Context) error {
				name := ctx.String("n")
				log.Info().Msgf("hello: %s,", name, "!")
				return nil
			},
		},
		cli.Command{
			Name:  "test3",
			Usage: "generate for test 3",
			Flags: []cli.Flag{},
			Action: func(ctx *cli.Context) error {
				name := ctx.String("n")
				log.Info().Msgf("hello: %s,", name, "!")
				return nil
			},
		},
	}

	err := cliApp.Run(os.Args)
	if err != nil {
		log.Error().Msgf("demo-cli execute error: %v\n", err)
		os.Exit(-1)
	}
}
