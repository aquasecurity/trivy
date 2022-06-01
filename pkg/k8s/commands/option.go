package commands

import (
	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"

	cmd "github.com/aquasecurity/trivy/pkg/commands/artifact"
)

func InitOption(ctx *cli.Context) (cmd.Option, error) {
	opt, err := cmd.NewOption(ctx)
	if err != nil {
		return cmd.Option{}, xerrors.Errorf("option error: %w", err)
	}

	// initialize options
	if err = opt.InitPreScanOptions(); err != nil {
		return cmd.Option{}, xerrors.Errorf("option initialize error: %w", err)
	}

	// --clear-cache, --download-db-only and --reset don't conduct the scan
	if opt.SkipScan() {
		return cmd.Option{}, nil
	}

	return opt, nil
}
