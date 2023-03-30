package main

import (
	"log"

	"github.com/aquasecurity/trivy/pkg/commands"
	"github.com/spf13/cobra/doc"
)

func main() {

	err := doc.GenMarkdownTree(commands.NewApp("v0.38"), "./docs/docs/references/cli")
	if err != nil {
		log.Fatal(err)
	}
}
