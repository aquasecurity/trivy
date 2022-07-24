package main

import (
	"context"
	"fmt"
	"os"

	"github.com/aquasecurity/trivy/pkg/commands"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/plugin"
)

var (
	version = "dev"
)

func main() {
	// Trivy behaves as the specified plugin.
	if runAsPlugin := os.Getenv("TRIVY_RUN_AS_PLUGIN"); runAsPlugin != "" {
		if !plugin.IsPredefined(runAsPlugin) {
			log.Fatal(fmt.Errorf("unknown plugin: %s", runAsPlugin))
		}
		if err := plugin.RunWithArgs(context.Background(), runAsPlugin, os.Args); err != nil {
			log.Fatal(err)
		}
	}

	app := commands.NewApp(version)
	if err := app.Execute(); err != nil {
		log.Fatal(err)
	}
}
