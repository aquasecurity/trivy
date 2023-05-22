package main

import (
	"context"
	"os"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/commands"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/plugin"

	_ "modernc.org/sqlite" // sqlite driver for RPM DB and Java DB
)

var (
	version = "dev"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	runAsPlugin := os.Getenv("TRIVY_RUN_AS_PLUGIN")

	if runAsPlugin == "" {
		app := commands.NewApp(version)
		return app.Execute()
	}

	// Reaching this point means Trivy behaves as the specified plugin.
	if !plugin.IsPredefined(runAsPlugin) {
		return xerrors.Errorf("unknown plugin: %s", runAsPlugin)
	}

	if err := plugin.RunWithArgs(context.Background(), runAsPlugin, os.Args[1:]); err != nil {
		return xerrors.Errorf("plugin error: %w", err)
	}

	return nil
}
