package main

import (
	"log"

	"github.com/aquasecurity/go-version/pkg/version"
)

func main() {
	if _, err := version.Parse("v0.1.2"); err != nil {
		log.Fatal(err)
	}
}
