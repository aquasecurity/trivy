package pkg

import (
	l "log"
	"os"
	"strings"

	"github.com/knqyf263/trivy/pkg/vulnsrc/vulnerability"

	"github.com/knqyf263/trivy/pkg/report"
	"github.com/knqyf263/trivy/pkg/scanner"
	"github.com/knqyf263/trivy/pkg/vulnsrc"

	"github.com/urfave/cli"
	"golang.org/x/xerrors"

	"github.com/knqyf263/trivy/pkg/db"
	"github.com/knqyf263/trivy/pkg/log"
)

func Run(c *cli.Context) (err error) {
	debug := c.Bool("debug")
	if err = log.InitLogger(debug); err != nil {
		l.Fatal(err)
	}

	args := c.Args()
	filePath := c.String("input")
	if filePath == "" && len(args) == 0 {
		return xerrors.New(`trivy" requires at least 1 argument or --input option.`)
	}

	o := c.String("output")
	output := os.Stdout
	if o != "" {
		if output, err = os.Create(o); err != nil {
			return xerrors.Errorf("failed to create an output file: %w", err)
		}
	}

	var severities []vulnerability.Severity
	for _, s := range strings.Split(c.String("severity"), ",") {
		severity, err := vulnerability.NewSeverity(s)
		if err != nil {
			return xerrors.Errorf("error in severity option: %w", err)
		}
		severities = append(severities, severity)
	}

	if err = db.Init(); err != nil {
		return xerrors.Errorf("error in vulnerability DB initialize: %w", err)
	}

	if err = vulnsrc.Update(); err != nil {
		return xerrors.Errorf("error in vulnerability DB update: %w", err)
	}

	var imageName string
	if filePath == "" {
		imageName = args[0]
	}
	results, err := scanner.ScanImage(imageName, filePath, severities)
	if err != nil {
		return xerrors.Errorf("error in image scan: %w", err)
	}

	var writer report.Writer
	switch c.String("format") {
	case "table":
		writer = &report.TableWriter{Output: output}
	case "json":
		writer = &report.JsonWriter{Output: output}
	default:
		xerrors.New("unknown format")
	}

	if err = writer.Write(results); err != nil {
		return err
	}

	return nil
}
