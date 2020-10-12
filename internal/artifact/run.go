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

// InitializeScanner type to define initialize function signature
type InitializeScanner func(context.Context, string, cache.ArtifactCache, cache.LocalArtifactCache, time.Duration) (
	scanner.Scanner, func(), error)

func initialize(c config.Config) (*cache.FSCache, bool, string, error) {
	if err := log.InitLogger(c.Debug, c.Quiet); err != nil {
		l.Fatal(err)
	}
	// configure cache dir
	utils.SetCacheDir(c.CacheDir)
	target := c.Target
	if c.Input != "" {
		target = c.Input
	}
	cacheClient, err := cache.NewFSCache(c.CacheDir)
	if err != nil {
		return nil, true, target, xerrors.Errorf("unable to initialize the cache: %w", err)
	}
	cacheOperation := operation.NewCache(cacheClient)
	log.Logger.Debugf("cache dir:  %s", utils.CacheDir())
	if c.Reset {
		return &cacheClient, true, target, cacheOperation.Reset()
	}
	if c.ClearCache {
		return &cacheClient, true, target, cacheOperation.ClearImages()
	}
	// download the database file
	noProgress := c.Quiet || c.NoProgress
	if err = operation.DownloadDB(c.AppVersion, c.CacheDir, noProgress, c.Light, c.SkipUpdate); err != nil {
		return &cacheClient, true, target, err
	}
	if c.DownloadDBOnly {
		return &cacheClient, true, target, nil
	}
	return &cacheClient, false, target, nil
}

func run(c config.Config, initializeScanner InitializeScanner) error {
	cacheClient, skip, target, err := initialize(c)
	defer func() {
		if cacheClient != nil {
			cacheClient.Close() // nolint: gosec
		}
	}()
	if err != nil || skip {
		return err
	}
	if err = db.Init(c.CacheDir); err != nil {
		return xerrors.Errorf("error in vulnerability DB initialize: %w", err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), c.Timeout)
	defer cancel()
	scanner, cleanup, err := initializeScanner(ctx, target, cacheClient, cacheClient, c.Timeout)
	if err != nil {
		return xerrors.Errorf("unable to initialize a scanner: %w", err)
	}
	defer cleanup()

	scanOptions := types.ScanOptions{
		VulnType:            c.VulnType,
		ScanRemovedPackages: c.ScanRemovedPkgs, // this is valid only for image subcommand
		ListAllPackages:     c.ListAllPkgs,
		SkipFiles:           c.SkipFiles,
		SkipDirectories:     c.SkipDirectories,
	}
	log.Logger.Debugf("Vulnerability type:  %s", scanOptions.VulnType)

	results, err := scanner.ScanArtifact(ctx, scanOptions)
	if err != nil {
		return xerrors.Errorf("error in image scan: %w", err)
	}

	vulnClient := initializeVulnerabilityClient()
	for i := range results {
		vulnClient.FillInfo(results[i].Vulnerabilities, results[i].Type)
		vulns, fErr := vulnClient.Filter(ctx, results[i].Vulnerabilities,
			c.Severities, c.IgnoreUnfixed, c.IgnoreFile, c.IgnorePolicy)
		if fErr != nil {
			return xerrors.Errorf("unable to filter vulnerabilities: %w", fErr)
		}
		results[i].Vulnerabilities = vulns
	}

	if err = report.WriteResults(c.Format, c.Output, c.Severities, results, c.Template, c.Light); err != nil {
		return xerrors.Errorf("unable to write results: %w", err)
	}
	checkExit(c.ExitCode, results)
	return nil
}

func checkExit(exitCode int, results report.Results) {
	if exitCode != 0 {
		for _, result := range results {
			if len(result.Vulnerabilities) > 0 {
				os.Exit(exitCode)
			}
		}
	}
}
