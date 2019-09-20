package main

import (
	l "log"
	"os"
	"strings"

	"github.com/aquasecurity/trivy/pkg/utils"

	"github.com/aquasecurity/trivy/pkg/vulnsrc/vulnerability"

	"github.com/urfave/cli"

	"github.com/aquasecurity/trivy/pkg"
	"github.com/aquasecurity/trivy/pkg/log"
)

var (
	version = "dev"
)

func main() {
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

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "format, f",
			Value: "table",
			Usage: "format (table, json)",
		},
		cli.StringFlag{
			Name:  "input, i",
			Value: "",
			Usage: "input file path instead of image name",
		},
		cli.StringFlag{
			Name:  "severity, s",
			Value: strings.Join(vulnerability.SeverityNames, ","),
			Usage: "severities of vulnerabilities to be displayed (comma separated)",
		},
		cli.StringFlag{
			Name:  "output, o",
			Usage: "output file name",
		},
		cli.IntFlag{
			Name:  "exit-code",
			Usage: "Exit code when vulnerabilities were found",
			Value: 0,
		},
		cli.BoolFlag{
			Name:  "skip-update",
			Usage: "skip db update",
		},
		cli.StringFlag{
			Name:  "only-update",
			Usage: "update db only specified distribution (comma separated)",
		},
		cli.BoolFlag{
			Name:  "reset",
			Usage: "remove all caches and database",
		},
		cli.BoolFlag{
			Name:  "clear-cache, c",
			Usage: "clear image caches",
		},
		cli.BoolFlag{
			Name:  "quiet, q",
			Usage: "suppress progress bar and log output",
		},
		cli.BoolFlag{
			Name:  "no-progress",
			Usage: "suppress progress bar",
		},
		cli.BoolFlag{
			Name:  "ignore-unfixed",
			Usage: "display only fixed vulnerabilities",
		},
		cli.BoolFlag{
			Name:  "refresh",
			Usage: "refresh DB (usually used after version update of trivy)",
		},
		cli.BoolFlag{
			Name:  "auto-refresh",
			Usage: "refresh DB automatically when updating version of trivy",
		},
		cli.BoolFlag{
			Name:  "debug, d",
			Usage: "debug mode",
		},
		cli.StringFlag{
			Name:  "vuln-type",
			Value: "os,library",
			Usage: "comma-separated list of vulnerability types (os,library)",
		},
		cli.StringFlag{
			Name:  "cache-dir",
			Value: utils.DefaultCacheDir(),
			Usage: "use as cache directory, but image cache is stored in /path/to/cache/fanal",
		},
	}

	app.Action = pkg.Run

	err := app.Run(os.Args)
	if err != nil {
		if log.Logger != nil {
			log.Fatal(err)
		}
		l.Fatal(err)
	}
}
