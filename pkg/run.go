package pkg

import (
	l "log"
	"os"
	"strings"

	"github.com/knqyf263/fanal/cache"

	"github.com/knqyf263/trivy/pkg/utils"

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
	log.Logger.Debugf("cache dir:  %s", utils.CacheDir())

	clean := c.Bool("clean")
	if clean {
		log.Logger.Info("Cleaning caches...")
		if err = cache.Clear(); err != nil {
			return xerrors.New("failed to remove image layer cache")
		}
		if err = os.RemoveAll(utils.CacheDir()); err != nil {
			return xerrors.New("failed to remove cache")
		}
		return nil
	}

	args := c.Args()
	filePath := c.String("input")
	if filePath == "" && len(args) == 0 {
		log.Logger.Info(`trivy" requires at least 1 argument or --input option.`)
		cli.ShowAppHelpAndExit(c, 1)
	}

	utils.Quiet = c.Bool("quiet")

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
			log.Logger.Infof("error in severity option: %s", err)
			cli.ShowAppHelpAndExit(c, 1)
		}
		severities = append(severities, severity)
	}

	if err = db.Init(); err != nil {
		return xerrors.Errorf("error in vulnerability DB initialize: %w", err)
	}

	if !c.Bool("skip-update") {
		if err = vulnsrc.Update(); err != nil {
			return xerrors.Errorf("error in vulnerability DB update: %w", err)
		}
	}

	ignoreUnfixed := c.Bool("ignore-unfixed")

	var imageName string
	if filePath == "" {
		imageName = args[0]
	}
	results, err := scanner.ScanImage(imageName, filePath, severities, ignoreUnfixed)
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
		return xerrors.Errorf("failed to write results: %w", err)
	}

	for _, result := range results {
		if len(result.Vulnerabilities) > 0 {
			os.Exit(c.Int("exit-code"))
		}
	}

	return nil
}
