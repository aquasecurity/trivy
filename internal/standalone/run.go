package standalone

import (
	"context"
	"io/ioutil"
	l "log"
	"os"
	"strings"

	"github.com/aquasecurity/trivy-db/pkg/db"

	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/trivy/internal/operation"
	"github.com/aquasecurity/trivy/internal/standalone/config"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/scanner"
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
	cacheClient, err := cache.NewFSCache(c.CacheDir)
	if err != nil {
		return xerrors.Errorf("unable to initialize the cache: %w", err)
	}

	cacheOperation := operation.NewCache(cacheClient)
	log.Logger.Debugf("cache dir:  %s", utils.CacheDir())

	if c.Reset {
		return cacheOperation.Reset()
	}
	if c.ClearCache {
		return cacheOperation.ClearImages()
	}

	// download the database file
	noProgress := c.Quiet || c.NoProgress
	if err = operation.DownloadDB(c.AppVersion, c.CacheDir, noProgress, c.Light, c.SkipUpdate); err != nil {
		return err
	}

	if c.DownloadDBOnly {
		return nil
	}

	if err = db.Init(c.CacheDir); err != nil {
		return xerrors.Errorf("error in vulnerability DB initialize: %w", err)
	}

	var scanner scanner.Scanner
	ctx := context.Background()

	cleanup := func() {}
	if c.Input != "" {
		// scan tar file
		scanner, err = initializeArchiveScanner(ctx, c.Input, cacheClient, cacheClient, c.Timeout)
		if err != nil {
			return xerrors.Errorf("unable to initialize the archive scanner: %w", err)
		}
	} else {
		// scan an image in Docker Engine or Docker Registry
		scanner, cleanup, err = initializeDockerScanner(ctx, c.ImageName, cacheClient, cacheClient, c.Timeout)
		if err != nil {
			return xerrors.Errorf("unable to initialize the docker scanner: %w", err)
		}
	}
	defer cleanup()

	scanOptions := types.ScanOptions{
		VulnType:            c.VulnType,
		ScanRemovedPackages: c.ScanRemovedPkgs,
	}
	log.Logger.Debugf("Vulnerability type:  %s", scanOptions.VulnType)

	results, err := scanner.ScanImage(scanOptions)
	if err != nil {
		return xerrors.Errorf("error in image scan: %w", err)
	}

	vulnClient := initializeVulnerabilityClient()
	for i := range results {
		vulnClient.FillInfo(results[i].Vulnerabilities, c.Light)
		results[i].Vulnerabilities = vulnClient.Filter(results[i].Vulnerabilities,
			c.Severities, c.IgnoreUnfixed, c.IgnoreFile)
	}

	template := c.Template

	if strings.HasPrefix(c.Template, "@") {
		buf, err := ioutil.ReadFile(strings.TrimPrefix(c.Template, "@"))
		if err != nil {
			return xerrors.Errorf("Error retrieving template from path: %w", err)
		}
		template = string(buf)
	}

	if err = report.WriteResults(c.Format, c.Output, results, template, c.Light); err != nil {
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
