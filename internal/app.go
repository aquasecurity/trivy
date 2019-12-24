package internal

import (
	"strings"
	"time"

	"github.com/urfave/cli"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/internal/client"
	"github.com/aquasecurity/trivy/internal/server"
	"github.com/aquasecurity/trivy/internal/standalone"
	"github.com/aquasecurity/trivy/pkg/utils"
	"github.com/aquasecurity/trivy/pkg/vulnerability"
)

var (
	templateFlag = cli.StringFlag{
		Name:   "template, t",
		Value:  "",
		Usage:  "output template",
		EnvVar: "TRIVY_TEMPLATE",
	}

	formatFlag = cli.StringFlag{
		Name:   "format, f",
		Value:  "table",
		Usage:  "format (table, json, template)",
		EnvVar: "TRIVY_FORMAT",
	}

	inputFlag = cli.StringFlag{
		Name:   "input, i",
		Value:  "",
		Usage:  "input file path instead of image name",
		EnvVar: "TRIVY_INPUT",
	}

	severityFlag = cli.StringFlag{
		Name:   "severity, s",
		Value:  strings.Join(types.SeverityNames, ","),
		Usage:  "severities of vulnerabilities to be displayed (comma separated)",
		EnvVar: "TRIVY_SEVERITY",
	}

	outputFlag = cli.StringFlag{
		Name:   "output, o",
		Usage:  "output file name",
		EnvVar: "TRIVY_OUTPUT",
	}

	exitCodeFlag = cli.IntFlag{
		Name:   "exit-code",
		Usage:  "Exit code when vulnerabilities were found",
		Value:  0,
		EnvVar: "TRIVY_EXIT_CODE",
	}

	skipUpdateFlag = cli.BoolFlag{
		Name:   "skip-update",
		Usage:  "skip db update",
		EnvVar: "TRIVY_SKIP_UPDATE",
	}

	downloadDBOnlyFlag = cli.BoolFlag{
		Name:   "download-db-only",
		Usage:  "download/update vulnerability database but don't run a scan",
		EnvVar: "TRIVY_DOWNLOAD_DB_ONLY",
	}

	resetFlag = cli.BoolFlag{
		Name:   "reset",
		Usage:  "remove all caches and database",
		EnvVar: "TRIVY_RESET",
	}

	clearCacheFlag = cli.BoolFlag{
		Name:   "clear-cache, c",
		Usage:  "clear image caches without scanning",
		EnvVar: "TRIVY_CLEAR_CACHE",
	}

	quietFlag = cli.BoolFlag{
		Name:   "quiet, q",
		Usage:  "suppress progress bar and log output",
		EnvVar: "TRIVY_QUIET",
	}

	noProgressFlag = cli.BoolFlag{
		Name:   "no-progress",
		Usage:  "suppress progress bar",
		EnvVar: "TRIVY_NO_PROGRESS",
	}

	ignoreUnfixedFlag = cli.BoolFlag{
		Name:   "ignore-unfixed",
		Usage:  "display only fixed vulnerabilities",
		EnvVar: "TRIVY_IGNORE_UNFIXED",
	}

	debugFlag = cli.BoolFlag{
		Name:   "debug, d",
		Usage:  "debug mode",
		EnvVar: "TRIVY_DEBUG",
	}

	vulnTypeFlag = cli.StringFlag{
		Name:   "vuln-type",
		Value:  "os,library",
		Usage:  "comma-separated list of vulnerability types (os,library)",
		EnvVar: "TRIVY_VULN_TYPE",
	}

	cacheDirFlag = cli.StringFlag{
		Name:   "cache-dir",
		Value:  utils.DefaultCacheDir(),
		Usage:  "use as cache directory, but image cache is stored in /path/to/cache/fanal",
		EnvVar: "TRIVY_CACHE_DIR",
	}

	ignoreFileFlag = cli.StringFlag{
		Name:   "ignorefile",
		Value:  vulnerability.DefaultIgnoreFile,
		Usage:  "specify .trivyignore file",
		EnvVar: "TRIVY_IGNOREFILE",
	}

	timeoutFlag = cli.DurationFlag{
		Name:   "timeout",
		Value:  time.Second * 60,
		Usage:  "docker timeout",
		EnvVar: "TRIVY_TIMEOUT",
	}

	lightFlag = cli.BoolFlag{
		Name:   "light",
		Usage:  "light mode: it's faster, but vulnerability descriptions and references are not displayed",
		EnvVar: "TRIVY_LIGHT",
	}

	token = cli.StringFlag{
		Name:   "token",
		Usage:  "for authentication",
		EnvVar: "TRIVY_TOKEN",
	}

	tokenHeader = cli.StringFlag{
		Name:   "token-header",
		Value:  "Trivy-Token",
		Usage:  "specify a header name for token",
		EnvVar: "TRIVY_TOKEN_HEADER",
	}
)

func NewApp(version string) *cli.App {
	cli.AppHelpTemplate = `NAME:
  {{.Name}}{{if .Usage}} - {{.Usage}}{{end}}
USAGE:
  {{if .UsageText}}{{.UsageText}}{{else}}{{.HelpName}} {{if .VisibleFlags}}[options]{{end}} {{if .ArgsUsage}}{{.ArgsUsage}}{{else}}[arguments...]{{end}}{{end}}{{if .Version}}{{if not .HideVersion}}
VERSION:
  {{.Version}}{{end}}{{end}}{{if .Description}}
DESCRIPTION:
  {{.Description}}{{end}}{{if len .Authors}}
AUTHOR{{with $length := len .Authors}}{{if ne 1 $length}}S{{end}}{{end}}:
  {{range $index, $author := .Authors}}{{if $index}}
  {{end}}{{$author}}{{end}}{{end}}{{if .VisibleCommands}}
OPTIONS:
  {{range $index, $option := .VisibleFlags}}{{if $index}}
  {{end}}{{$option}}{{end}}{{end}}
`
	app := cli.NewApp()
	app.Name = "trivy"
	app.Version = version
	app.ArgsUsage = "image_name"

	app.Usage = "A simple and comprehensive vulnerability scanner for containers"

	app.EnableBashCompletion = true

	app.Flags = []cli.Flag{
		templateFlag,
		formatFlag,
		inputFlag,
		severityFlag,
		outputFlag,
		exitCodeFlag,
		skipUpdateFlag,
		downloadDBOnlyFlag,
		resetFlag,
		clearCacheFlag,
		quietFlag,
		noProgressFlag,
		ignoreUnfixedFlag,
		debugFlag,
		vulnTypeFlag,
		cacheDirFlag,
		ignoreFileFlag,
		timeoutFlag,
		lightFlag,

		// deprecated options
		cli.StringFlag{
			Name:   "only-update",
			Usage:  "deprecated",
			EnvVar: "TRIVY_ONLY_UPDATE",
		},
		cli.BoolFlag{
			Name:   "refresh",
			Usage:  "deprecated",
			EnvVar: "TRIVY_REFRESH",
		},
		cli.BoolFlag{
			Name:   "auto-refresh",
			Usage:  "deprecated",
			EnvVar: "TRIVY_AUTO_REFRESH",
		},
	}

	app.Commands = []cli.Command{
		NewClientCommand(),
		NewServerCommand(),
	}

	app.Action = standalone.Run
	return app
}

func NewClientCommand() cli.Command {
	return cli.Command{
		Name:    "client",
		Aliases: []string{"c"},
		Usage:   "client mode",
		Action:  client.Run,
		Flags: []cli.Flag{
			templateFlag,
			formatFlag,
			inputFlag,
			severityFlag,
			outputFlag,
			exitCodeFlag,
			clearCacheFlag,
			quietFlag,
			ignoreUnfixedFlag,
			debugFlag,
			vulnTypeFlag,
			ignoreFileFlag,
			cacheDirFlag,
			timeoutFlag,

			// original flags
			token,
			tokenHeader,
			cli.StringFlag{
				Name:   "remote",
				Value:  "http://localhost:4954",
				Usage:  "server address",
				EnvVar: "TRIVY_REMOTE",
			},
			cli.StringSliceFlag{
				Name:   "custom-headers",
				Usage:  "custom headers",
				EnvVar: "TRIVY_CUSTOM_HEADERS",
			},
		},
	}
}

func NewServerCommand() cli.Command {
	return cli.Command{
		Name:    "server",
		Aliases: []string{"s"},
		Usage:   "server mode",
		Action:  server.Run,
		Flags: []cli.Flag{
			skipUpdateFlag,
			downloadDBOnlyFlag,
			resetFlag,
			quietFlag,
			debugFlag,
			cacheDirFlag,

			// original flags
			token,
			tokenHeader,
			cli.StringFlag{
				Name:   "listen",
				Value:  "localhost:4954",
				Usage:  "listen address",
				EnvVar: "TRIVY_LISTEN",
			},
		},
	}
}
