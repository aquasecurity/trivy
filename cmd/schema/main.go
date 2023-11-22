package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/aquasecurity/trivy/pkg/rego/schemas"
)

// generate a json schema document for cloud rego input (state.State)

const schemaPath = "pkg/rego/schemas/cloud.json"

func main() {
	if err := rootCmd.Execute(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use: "schema",
}

func init() {
	rootCmd.AddCommand(generateCmd)
	rootCmd.AddCommand(verifyCmd)
}

var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "generate a json schema document for cloud rego input (state.State)",
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceErrors = true
		cmd.SilenceUsage = true
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
		fmt.Println("done")
		return nil
	},
}

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "verify that the schema is up to date",
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceErrors = true
		cmd.SilenceUsage = true
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
		if string(data) != string(existing) {
			return fmt.Errorf("schema is out of date:\n\nplease run 'make schema' and commit the changes")
		}
		fmt.Println("schema is valid")
		return nil
	},
}
