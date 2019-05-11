package remic

import (
	l "log"
	"os"
	"strings"

	"github.com/knqyf263/trivy/pkg/scanner"

	"github.com/knqyf263/trivy/pkg/vulnsrc/vulnerability"

	"github.com/knqyf263/trivy/pkg/vulnsrc"

	"github.com/urfave/cli"
	"golang.org/x/xerrors"

	"github.com/knqyf263/trivy/pkg/db"
	"github.com/knqyf263/trivy/pkg/log"
	"github.com/knqyf263/trivy/pkg/report"
)

func Run(c *cli.Context) (err error) {
	debug := c.Bool("debug")
	if err = log.InitLogger(debug); err != nil {
		l.Fatal(err)
	}

	args := c.Args()
	if len(args) == 0 {
		log.Logger.Info(`remic" requires at least 1 argument.`)
		cli.ShowAppHelpAndExit(c, 1)
	}

	o := c.String("output")
	output := os.Stdout
	if o != "" {
		if output, err = os.Create(o); err != nil {
			return err
		}
	}

	var severities []vulnerability.Severity
	for _, s := range strings.Split(c.String("severity"), ",") {
		severity, err := vulnerability.NewSeverity(s)
		if err != nil {
			return err
		}
		severities = append(severities, severity)
	}

	if err = db.Init(); err != nil {
		return err
	}

	if !c.Bool("skip-update") {
		if err = vulnsrc.Update(); err != nil {
			return xerrors.Errorf("error in vulnerability DB update: %w", err)
		}
	}

	fileName := args[0]
	f, err := os.Open(fileName)
	if err != nil {
		return xerrors.Errorf("failed to open a file: %w", err)
	}
	defer f.Close()

	ignoreUnfixed := c.Bool("ignore-unfixed")
	result, err := scanner.ScanFile(f, severities, ignoreUnfixed)
	if err != nil {
		return xerrors.Errorf("failed to scan a file: %w", err)
	}

	var writer report.Writer
	switch c.String("format") {
	case "table":
		writer = &report.TableWriter{Output: output}
	case "json":
		writer = &report.JsonWriter{Output: output}
	default:
		return xerrors.New("unknown format")
	}

	if err = writer.Write([]report.Result{result}); err != nil {
		return xerrors.Errorf("failed to write results: %w", err)
	}

	exitCode := c.Int("exit-code")
	if exitCode != 0 {
		for _, result := range []report.Result{result} {
			if len(result.Vulnerabilities) > 0 {
				os.Exit(exitCode)
			}
		}
	}

	return nil
}
