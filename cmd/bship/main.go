package main

import (
	"os"

	bship "github.com/seeton/BottleShipCrypt"
)

func main() {
	os.Exit(bship.RunCLI(os.Args[1:], os.Stdout, os.Stderr))
}
