//go:build mage_docs

package main

import (
	"github.com/spf13/cobra/doc"

	"github.com/aquasecurity/trivy/pkg/commands"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
)

// Generate CLI references
func main() {
	ver, err := version()
	if err != nil {
		log.Fatal(err)
	}
	// Set a dummy path for the documents
	flag.CacheDirFlag.Default = "/path/to/cache"
	flag.ModuleDirFlag.Default = "$HOME/.trivy/modules"

	cmd := commands.NewApp(ver)
	cmd.DisableAutoGenTag = true
	if err = doc.GenMarkdownTree(cmd, "./docs/docs/references/configuration/cli"); err != nil {
		log.Fatal(err)
	}
}
