package main

import (
	"os"

	"github.com/andrewkroh/flowbeat/cmd"

	_ "github.com/andrewkroh/flowbeat/include"
)

func main() {
	if err := cmd.RootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
