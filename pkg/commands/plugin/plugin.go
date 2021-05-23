package plugin

import (
	"context"

	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/commands/option"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/plugin"
)

// Install installs a plugin
func Install(c *cli.Context) error {
	if c.NArg() != 1 {
		cli.ShowSubcommandHelpAndExit(c, 1)
	}

	if err := initLogger(c); err != nil {
		return xerrors.Errorf("initialize error: %w", err)
	}

	url := c.Args().First()
	if _, err := plugin.Install(c.Context, url, true); err != nil {
		return xerrors.Errorf("plugin install error: %w", err)
	}

	return nil
}

// Uninstall uninstalls the plugin
func Uninstall(c *cli.Context) error {
	if c.NArg() != 1 {
		cli.ShowSubcommandHelpAndExit(c, 1)
	}

	if err := initLogger(c); err != nil {
		return xerrors.Errorf("initialize error: %w", err)
	}

	pluginName := c.Args().First()
	if err := plugin.Uninstall(pluginName); err != nil {
		return xerrors.Errorf("plugin uninstall error: %w", err)
	}

	return nil
}

// Run runs the plugin
func Run(c *cli.Context) error {
	if c.NArg() < 1 {
		cli.ShowSubcommandHelpAndExit(c, 1)
	}

	if err := initLogger(c); err != nil {
		return xerrors.Errorf("initialize error: %w", err)
	}

	url := c.Args().First()
	args := c.Args().Tail()
	return RunWithArgs(c.Context, url, args)
}

// RunWithArgs runs the plugin with arguments
func RunWithArgs(ctx context.Context, url string, args []string) error {
	pl, err := plugin.Install(ctx, url, false)
	if err != nil {
		return xerrors.Errorf("plugin install error: %w", err)
	}

	if err = pl.Run(ctx, args); err != nil {
		return xerrors.Errorf("unable to run %s plugin: %w", pl.Name, err)
	}
	return nil
}

// LoadCommands loads plugins as subcommands
func LoadCommands() cli.Commands {
	var commands cli.Commands
	plugins, err := plugin.LoadAll()
	if err != nil {
		log.Logger.Debugf("no plugins were loaded")
		return nil
	}
	for _, p := range plugins {
		cmd := &cli.Command{
			Name:  p.Name,
			Usage: p.Usage,
			Action: func(c *cli.Context) error {
				if err := initLogger(c); err != nil {
					return xerrors.Errorf("initialize error: %w", err)
				}

				if err := p.Run(c.Context, c.Args().Slice()); err != nil {
					return xerrors.Errorf("plugin error: %w", err)
				}
				return nil
			},
			SkipFlagParsing: true,
		}
		commands = append(commands, cmd)
	}
	return commands
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
