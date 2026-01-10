package main

import (
	"fmt"
	"os"

	"github.com/Sergeydigl3/zapret-nix/cmd/zapret/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
