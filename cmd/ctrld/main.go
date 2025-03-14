package main

import (
	"os"

	"github.com/Control-D-Inc/ctrld/cmd/cli"
)

func main() {
	cli.Main()
	// make sure we exit with 0 if there are no errors
	os.Exit(0)
}
