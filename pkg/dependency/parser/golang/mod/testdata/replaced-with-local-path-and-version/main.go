package main

import (
	"log"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/golang/mod"
)

func main() {
	if _, err := mod.Parse(nil); err != nil {
		log.Fatal(err)
	}
}
