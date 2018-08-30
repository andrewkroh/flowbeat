package cmd

import (
	"github.com/andrewkroh/flowbeat/beater"

	cmd "github.com/elastic/beats/libbeat/cmd"
)

// Name of this beat
var Name = "flowbeat"

const Version = "0.2.1"

// RootCmd to handle beats cli
var RootCmd = cmd.GenRootCmd(Name, Version, beater.New)
