package main

import (
	"os"
	"strings"

	"github.com/knqyf263/trivy/pkg/vulnsrc/vulnerability"

	"github.com/knqyf263/trivy/pkg/remic"
	"github.com/urfave/cli"

	"github.com/knqyf263/trivy/pkg/log"
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
	app.Name = "remic"
	app.Version = "0.0.1"
	app.ArgsUsage = "file"

	app.Usage = "A simple and fast tool for detecting vulnerabilities in application dependencies"

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "format, f",
			Value: "table",
			Usage: "format (table, json)",
		},
		cli.StringFlag{
			Name:  "severity, s",
			Value: strings.Join(vulnerability.SeverityNames, ","),
			Usage: "severity of vulnerabilities to be displayed",
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
			Name:  "ignore-unfixed",
			Usage: "display only fixed vulnerabilities",
		},
		cli.BoolFlag{
			Name:  "debug, d",
			Usage: "debug mode",
		},
	}

	app.Action = func(c *cli.Context) error {
		return remic.Run(c)
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Logger.Fatal(err)
	}
}
