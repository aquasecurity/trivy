package artifact

import (
	"context"
	l "log"
	"os"
	"time"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/internal/artifact/config"
	"github.com/aquasecurity/trivy/internal/operation"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/scanner"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/utils"
)

type InitializeScanner func(context.Context, string, cache.ArtifactCache, cache.LocalArtifactCache, time.Duration) (
	scanner.Scanner, func(), error)

func run(c config.Config, initializeScanner InitializeScanner) error {
	if err := log.InitLogger(c.Debug, c.Quiet); err != nil {
		l.Fatal(err)
	}

	// configure cache dir
	utils.SetCacheDir(c.CacheDir)
	cacheClient, err := cache.NewFSCache(c.CacheDir)
	if err != nil {
		return xerrors.Errorf("unable to initialize the cache: %w", err)
	}
	defer cacheClient.Close()

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
	defer db.Close()

	target := c.Target
	if c.Input != "" {
		target = c.Input
	}

	ctx := context.Background()
	scanner, cleanup, err := initializeScanner(ctx, target, cacheClient, cacheClient, c.Timeout)
	if err != nil {
		return xerrors.Errorf("unable to initialize a scanner: %w", err)
	}
	defer cleanup()

	scanOptions := types.ScanOptions{
		VulnType:            c.VulnType,
		ScanRemovedPackages: c.ScanRemovedPkgs, // this is valid only for image subcommand
	}
	log.Logger.Debugf("Vulnerability type:  %s", scanOptions.VulnType)

	results, err := scanner.ScanArtifact(ctx, scanOptions)
	if err != nil {
		return xerrors.Errorf("error in image scan: %w", err)
	}

	vulnClient := initializeVulnerabilityClient()
	for i := range results {
		vulnClient.FillInfo(results[i].Vulnerabilities, results[i].Type)
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
