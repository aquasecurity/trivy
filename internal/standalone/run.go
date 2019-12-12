package standalone

import (
	l "log"
	"os"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/internal/operation"
	"github.com/aquasecurity/trivy/internal/standalone/config"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/utils"
	"github.com/urfave/cli"
	"golang.org/x/xerrors"
)

func Run(cliCtx *cli.Context) error {
	c, err := config.New(cliCtx)
	if err != nil {
		return err
	}
	return run(c)
}

func run(c config.Config) (err error) {
	if err = log.InitLogger(c.Debug, c.Quiet); err != nil {
		l.Fatal(err)
	}

	// initialize config
	if err = c.Init(); err != nil {
		return xerrors.Errorf("failed to initialize options: %w", err)
	}

	// configure cache dir
	utils.SetCacheDir(c.CacheDir)
	log.Logger.Debugf("cache dir:  %s", utils.CacheDir())

	if c.Reset {
		return operation.Reset()
	}

	if c.ClearCache {
		return operation.ClearCache()
	}

	if err = db.Init(c.CacheDir); err != nil {
		return xerrors.Errorf("error in vulnerability DB initialize: %w", err)
	}

	// download the database file
	if err = operation.DownloadDB(c.AppVersion, c.CacheDir, c.Light, c.SkipUpdate); err != nil {
		return err
	}

	if c.DownloadDBOnly {
		return nil
	}

	scanOptions := types.ScanOptions{
		VulnType: c.VulnType,
		Timeout:  c.Timeout,
	}
	log.Logger.Debugf("Vulnerability type:  %s", scanOptions.VulnType)

	scanner := initializeScanner()
	results, err := scanner.ScanImage(c.ImageName, c.Input, scanOptions)
	if err != nil {
		return xerrors.Errorf("error in image scan: %w", err)
	}

	vulnClient := initializeVulnerabilityClient()
	for i := range results {
		vulnClient.FillInfo(results[i].Vulnerabilities, c.Light)
		results[i].Vulnerabilities = vulnClient.Filter(results[i].Vulnerabilities,
			c.Severities, c.IgnoreUnfixed, c.IgnoreFile)
	}

	if err = report.WriteResults(c.Format, c.Output, results, c.Template, c.Light); err != nil {
		return xerrors.Errorf("unable to write results: %w", err)
	}

	if c.ExitCode != 0 {
		for _, result := range results {
			if len(result.Vulnerabilities) > 0 {
				os.Exit(c.ExitCode)
			}
		}
	}
	return nil
}
