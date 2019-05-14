package main

import (
	l "log"
	"os"
	"strings"

	"github.com/knqyf263/trivy/pkg/vulnsrc/vulnerability"

	"github.com/urfave/cli"

	"github.com/knqyf263/trivy/pkg"
	"github.com/knqyf263/trivy/pkg/log"
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
			Name:  "debug, d",
			Usage: "debug mode",
		},
	}

	app.Action = func(c *cli.Context) error {
		return pkg.Run(c)
	}

	err := app.Run(os.Args)
	if err != nil {
		if log.Logger != nil {
			log.Logger.Fatal(err)
		}
		l.Fatal(err)
	}
}
