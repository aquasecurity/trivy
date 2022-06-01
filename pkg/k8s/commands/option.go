package commands

import (
	cmd "github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"
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

	return opt, nil
}
