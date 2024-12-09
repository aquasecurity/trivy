//go:build mage_schema

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"log"
	"os"

	"github.com/aquasecurity/trivy/pkg/iac/rego/schemas"
)

const (
	schemaPath = "pkg/iac/rego/schemas/cloud.json"
)

func main() {
	if len(os.Args) < 3 {
		log.Fatalf("invalid schema command args: %s", os.Args)
	}

	switch os.Args[2] {
	case "generate":
		if err := GenSchema(); err != nil {
			log.Fatalf(err.Error())
		}
		log.Println("schema generated")
	case "verify":
		if err := VerifySchema(); err != nil {
			log.Fatalf(err.Error())
		}
		log.Println("schema valid")
	}
}

// GenSchema generates the Trivy IaC schema
func GenSchema() error {
	schema, err := schemas.Build()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(schemaPath, data, 0600); err != nil {
		return err
	}
	return nil
}

// VerifySchema verifies a generated schema for validity
func VerifySchema() error {
	schema, err := schemas.Build()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		return err
	}
	existing, err := os.ReadFile(schemaPath)
	if err != nil {
		return err
	}
	if !bytes.Equal(data, existing) {
		return errors.New("schema is out of date:\n\nplease run 'mage schema:generate' and commit the changes\n")
	}
	return nil
}
