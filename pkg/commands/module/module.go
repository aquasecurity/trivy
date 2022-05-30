package module

import (
	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/commands/option"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/module"
)

// Install installs a module
func Install(c *cli.Context) error {
	if c.NArg() != 1 {
		cli.ShowSubcommandHelpAndExit(c, 1)
	}

	if err := initLogger(c); err != nil {
		return xerrors.Errorf("log initialization error: %w", err)
	}

	repo := c.Args().First()
	if err := module.Install(c.Context, repo, c.Bool("quiet"), c.Bool("insecure")); err != nil {
		return xerrors.Errorf("module installation error: %w", err)
	}

	return nil
}

func initLogger(ctx *cli.Context) error {
	conf, err := option.NewGlobalOption(ctx)
	if err != nil {
		return xerrors.Errorf("config error: %w", err)
	}

	if err = log.InitLogger(conf.Debug, conf.Quiet); err != nil {
		return xerrors.Errorf("failed to initialize a logger: %w", err)
	}
	return nil
}
