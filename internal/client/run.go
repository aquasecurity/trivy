package client

import (
	"context"
	"os"

	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/trivy/internal/client/config"
	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/rpc/client"
	"github.com/aquasecurity/trivy/pkg/scanner"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/utils"
)

// Run runs the scan
func Run(cliCtx *cli.Context) error {
	c, err := config.New(cliCtx)
	if err != nil {
		return err
	}
	return run(c)
}

func run(c config.Config) (err error) {
	if err = initialize(&c); err != nil {
		return err
	}

	if c.ClearCache {
		log.Logger.Warn("A client doesn't have image cache")
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.Timeout)
	defer cancel()

	s, cleanup, err := initializeScanner(ctx, c)
	if err != nil {
		return err
	}
	defer cleanup()

	scanOptions := types.ScanOptions{
		VulnType:            c.VulnType,
		ScanRemovedPackages: c.ScanRemovedPkgs,
	}
	log.Logger.Debugf("Vulnerability type:  %s", scanOptions.VulnType)

	results, err := s.ScanArtifact(ctx, scanOptions)
	if err != nil {
		return xerrors.Errorf("error in image scan: %w", err)
	}

	vulnClient := initializeVulnerabilityClient()
	for i := range results {
		vulns, err := vulnClient.Filter(ctx, results[i].Vulnerabilities,
			c.Severities, c.IgnoreUnfixed, c.IgnoreFile, c.IgnorePolicy)
		if err != nil {
			return err
		}
		results[i].Vulnerabilities = vulns
	}

	if err = report.WriteResults(c.Format, c.Output, c.Severities, results, c.Template, false); err != nil {
		return xerrors.Errorf("unable to write results: %w", err)
	}

	exit(c, results)

	return nil
}

func initialize(c *config.Config) error {
	// Initialize logger
	if err := log.InitLogger(c.Debug, c.Quiet); err != nil {
		return xerrors.Errorf("failed to initialize a logger: %w", err)
	}

	// Initialize config
	if err := c.Init(); err != nil {
		return xerrors.Errorf("failed to initialize options: %w", err)
	}

	// configure cache dir
	utils.SetCacheDir(c.CacheDir)
	log.Logger.Debugf("cache dir:  %s", utils.CacheDir())

	return nil
}

func initializeScanner(ctx context.Context, c config.Config) (scanner.Scanner, func(), error) {
	remoteCache := cache.NewRemoteCache(cache.RemoteURL(c.RemoteAddr), c.CustomHeaders)

	// It doesn't analyze apk commands by default.
	disabledAnalyzers := []analyzer.Type{analyzer.TypeApkCommand}
	if c.ScanRemovedPkgs {
		disabledAnalyzers = []analyzer.Type{}
	}

	if c.Input != "" {
		// Scan tar file
		s, err := initializeArchiveScanner(ctx, c.Input, remoteCache,
			client.CustomHeaders(c.CustomHeaders), client.RemoteURL(c.RemoteAddr), c.Timeout, disabledAnalyzers)
		if err != nil {
			return scanner.Scanner{}, nil, xerrors.Errorf("unable to initialize the archive scanner: %w", err)
		}
		return s, func() {}, nil
	}

	// Scan an image in Docker Engine or Docker Registry
	s, cleanup, err := initializeDockerScanner(ctx, c.Target, remoteCache,
		client.CustomHeaders(c.CustomHeaders), client.RemoteURL(c.RemoteAddr), c.Timeout, disabledAnalyzers)
	if err != nil {
		return scanner.Scanner{}, nil, xerrors.Errorf("unable to initialize the docker scanner: %w", err)
	}

	return s, cleanup, nil
}

func exit(c config.Config, results report.Results) {
	if c.ExitCode != 0 {
		for _, result := range results {
			if len(result.Vulnerabilities) > 0 {
				os.Exit(c.ExitCode)
			}
		}
	}
}
