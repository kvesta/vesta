package main

import (
	"log"
	"os"

	"vesta/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		log.Printf("%v", err)
		os.Exit(1)
	}
}
