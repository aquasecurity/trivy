package pkg

import (
	l "log"
	"os"
	"strings"

	"github.com/urfave/cli"
	"golang.org/x/xerrors"

	"github.com/knqyf263/trivy/pkg/db"
	"github.com/knqyf263/trivy/pkg/log"
	"github.com/knqyf263/trivy/pkg/report"
	"github.com/knqyf263/trivy/pkg/scanner"
	"github.com/knqyf263/trivy/pkg/vulnsrc/nvd"
)

func Run(c *cli.Context) (err error) {
	debug := c.Bool("debug")
	if err = log.InitLogger(debug); err != nil {
		l.Fatal(err)
	}

	args := c.Args()
	if len(args) == 0 {
		return xerrors.New(`trivy" requires at least 1 argument.`)
	}

	o := c.String("output")
	output := os.Stdout
	if o != "" {
		if output, err = os.Create(o); err != nil {
			return err
		}
	}

	var severities []nvd.Severity
	for _, s := range strings.Split(c.String("severity"), ",") {
		severity, err := nvd.NewSeverity(s)
		if err != nil {
			return err
		}
		severities = append(severities, severity)
	}

	if err = db.Init(); err != nil {
		return err
	}

	if err = nvd.Update(); err != nil {
		return err
	}

	fileName := args[0]
	f, err := os.Open(fileName)
	if err != nil {
		return err
	}
	defer f.Close()

	vulns, err := scanner.Scan(f, severities)
	if err != nil {
		return err
	}
	result := &report.Result{
		FileName:        f.Name(),
		Vulnerabilities: vulns,
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

	if err = writer.Write(result); err != nil {
		return err
	}

	return nil
}
