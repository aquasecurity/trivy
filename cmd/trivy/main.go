package main

import (
	"context"
	"os"
	"runtime/pprof"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/commands"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/plugin"
)

var (
	version = "dev"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
	{
		fMem, err := os.Create("mem.profile")
		if err != nil {
			panic("could not create memory profile: " + err.Error())
		}
		defer fMem.Close()
		if err := pprof.WriteHeapProfile(fMem); err != nil {
			panic("could not write memory profile: " + err.Error())
		}
	}
}

func run() error {
	// Trivy behaves as the specified plugin.
	if runAsPlugin := os.Getenv("TRIVY_RUN_AS_PLUGIN"); runAsPlugin != "" {
		if !plugin.IsPredefined(runAsPlugin) {
			return xerrors.Errorf("unknown plugin: %s", runAsPlugin)
		}
		if err := plugin.RunWithArgs(context.Background(), runAsPlugin, os.Args[1:]); err != nil {
			return xerrors.Errorf("plugin error: %w", err)
		}
		return nil
	}

	app := commands.NewApp(version)
	if err := app.Execute(); err != nil {
		return err
	}
	return nil
}
