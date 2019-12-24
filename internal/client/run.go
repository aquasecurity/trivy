package client

import (
	"os"

	"github.com/urfave/cli"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/internal/client/config"
	"github.com/aquasecurity/trivy/internal/operation"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/rpc/client/library"
	"github.com/aquasecurity/trivy/pkg/rpc/client/ospkg"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/utils"
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
		return xerrors.Errorf("failed to initialize a logger: %w", err)
	}

	// initialize config
	if err = c.Init(); err != nil {
		return xerrors.Errorf("failed to initialize options: %w", err)
	}

	// configure cache dir
	utils.SetCacheDir(c.CacheDir)
	log.Logger.Debugf("cache dir:  %s", utils.CacheDir())

	if c.ClearCache {
		return operation.ClearCache()
	}

	scanOptions := types.ScanOptions{
		VulnType:  c.VulnType,
		Timeout:   c.Timeout,
		RemoteURL: c.RemoteAddr,
	}
	log.Logger.Debugf("Vulnerability type:  %s", scanOptions.VulnType)

	scanner := initializeScanner(ospkg.CustomHeaders(c.CustomHeaders), library.CustomHeaders(c.CustomHeaders),
		ospkg.RemoteURL(c.RemoteAddr), library.RemoteURL(c.RemoteAddr))
	results, err := scanner.ScanImage(c.ImageName, c.Input, scanOptions)
	if err != nil {
		return xerrors.Errorf("error in image scan: %w", err)
	}

	vulnClient := initializeVulnerabilityClient()
	for i := range results {
		results[i].Vulnerabilities = vulnClient.Filter(results[i].Vulnerabilities,
			c.Severities, c.IgnoreUnfixed, c.IgnoreFile)
	}

	if err = report.WriteResults(c.Format, c.Output, results, c.Template, false); err != nil {
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
