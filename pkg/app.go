package pkg

import (
	"strings"
	"time"

	"github.com/aquasecurity/trivy/pkg/vulnerability"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/utils"
	"github.com/urfave/cli"
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
		cli.StringFlag{
			Name:   "template, t",
			Value:  "",
			Usage:  "output template",
			EnvVar: "TRIVY_TEMPLATE",
		},
		cli.StringFlag{
			Name:   "format, f",
			Value:  "table",
			Usage:  "format (table, json, template)",
			EnvVar: "TRIVY_FORMAT",
		},
		cli.StringFlag{
			Name:   "input, i",
			Value:  "",
			Usage:  "input file path instead of image name",
			EnvVar: "TRIVY_INPUT",
		},
		cli.StringFlag{
			Name:   "severity, s",
			Value:  strings.Join(types.SeverityNames, ","),
			Usage:  "severities of vulnerabilities to be displayed (comma separated)",
			EnvVar: "TRIVY_SEVERITY",
		},
		cli.StringFlag{
			Name:   "output, o",
			Usage:  "output file name",
			EnvVar: "TRIVY_OUTPUT",
		},
		cli.IntFlag{
			Name:   "exit-code",
			Usage:  "Exit code when vulnerabilities were found",
			Value:  0,
			EnvVar: "TRIVY_EXIT_CODE",
		},
		cli.BoolFlag{
			Name:   "skip-update",
			Usage:  "skip db update",
			EnvVar: "TRIVY_SKIP_UPDATE",
		},
		cli.BoolFlag{
			Name:   "download-db-only",
			Usage:  "download/update vulnerability database but don't run a scan",
			EnvVar: "TRIVY_DOWNLOAD_DB_ONLY",
		},
		cli.BoolFlag{
			Name:   "reset",
			Usage:  "remove all caches and database",
			EnvVar: "TRIVY_RESET",
		},
		cli.BoolFlag{
			Name:   "clear-cache, c",
			Usage:  "clear image caches",
			EnvVar: "TRIVY_CLEAR_CACHE",
		},
		cli.BoolFlag{
			Name:   "quiet, q",
			Usage:  "suppress progress bar and log output",
			EnvVar: "TRIVY_QUIET",
		},
		cli.BoolFlag{
			Name:   "no-progress",
			Usage:  "suppress progress bar",
			EnvVar: "TRIVY_NO_PROGRESS",
		},
		cli.BoolFlag{
			Name:   "ignore-unfixed",
			Usage:  "display only fixed vulnerabilities",
			EnvVar: "TRIVY_IGNORE_UNFIXED",
		},
		cli.BoolFlag{
			Name:   "debug, d",
			Usage:  "debug mode",
			EnvVar: "TRIVY_DEBUG",
		},
		cli.StringFlag{
			Name:   "vuln-type",
			Value:  "os,library",
			Usage:  "comma-separated list of vulnerability types (os,library)",
			EnvVar: "TRIVY_VULN_TYPE",
		},
		cli.StringFlag{
			Name:   "cache-dir",
			Value:  utils.DefaultCacheDir(),
			Usage:  "use as cache directory, but image cache is stored in /path/to/cache/fanal",
			EnvVar: "TRIVY_CACHE_DIR",
		},
		cli.StringFlag{
			Name:   "ignorefile",
			Value:  vulnerability.DefaultIgnoreFile,
			Usage:  "specify .trivyignore file",
			EnvVar: "TRIVY_IGNOREFILE",
		},
		cli.DurationFlag{
			Name:   "timeout",
			Value:  time.Second * 60,
			Usage:  "docker timeout",
			EnvVar: "TRIVY_TIMEOUT",
		},
		cli.BoolFlag{
			Name:  "light",
			Usage: "light mode: it's faster, but vulnerability descriptions and references are not displayed",
		},

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

	app.Action = Run
	return app
}
