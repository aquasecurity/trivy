package main

import (
	"context"
	"errors"
	"os"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/commands"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/plugin"
	"github.com/aquasecurity/trivy/pkg/types"

	_ "modernc.org/sqlite" // sqlite driver for RPM DB and Java DB
	"github.com/fatih/color" // Import the color package
)

func main() {
	if err := run(); err != nil {
		var exitError *types.ExitError
		if errors.As(err, &exitError) {
			os.Exit(exitError.Code)
		}
		log.Fatal("Fatal error", log.Err(err))
	}
}

func run() error {
	// Trivy behaves as the specified plugin.
	if runAsPlugin := os.Getenv("TRIVY_RUN_AS_PLUGIN"); runAsPlugin != "" {
		log.InitLogger(false, false)
		if err := plugin.Run(context.Background(), runAsPlugin, plugin.Options{Args: os.Args[1:]}); err != nil {
			return xerrors.Errorf("plugin error: %w", err)
		}
		return nil
	}

	app := commands.NewApp()

	// Initialize color settings based on the --color flag
	colorFlag := app.PersistentFlags().Lookup("color")
	if colorFlag != nil {
		switch colorFlag.Value.String() {
		case "true":
			color.NoColor = false
		case "false":
			color.NoColor = true
		case "auto":
			// Default behavior, let the color package decide
		}
	}

	if err := app.Execute(); err != nil {
		return err
	}
	return nil
}
