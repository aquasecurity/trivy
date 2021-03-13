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

func run(conf config.Config) error {
	ctx, cancel := context.WithTimeout(context.Background(), conf.Timeout)
	defer cancel()

	return runWithContext(ctx, conf)
}

func runWithContext(ctx context.Context, conf config.Config) error {
	if err := initialize(&conf); err != nil {
		return xerrors.Errorf("initialize error: %w", err)
	}

	if conf.ClearCache {
		log.Logger.Warn("A client doesn't have image cache")
		return nil
	}

	s, cleanup, err := initializeScanner(ctx, conf)
	if err != nil {
		return xerrors.Errorf("scanner initialize error: %w", err)
	}
	defer cleanup()

	scanOptions := types.ScanOptions{
		VulnType:            conf.VulnType,
		ScanRemovedPackages: conf.ScanRemovedPkgs,
	}
	log.Logger.Debugf("Vulnerability type:  %s", scanOptions.VulnType)

	results, err := s.ScanArtifact(ctx, scanOptions)
	if err != nil {
		return xerrors.Errorf("error in image scan: %w", err)
	}

	vulnClient := initializeVulnerabilityClient()
	for i := range results {
		vulns, err := vulnClient.Filter(ctx, results[i].Vulnerabilities,
			conf.Severities, conf.IgnoreUnfixed, conf.IgnoreFile, conf.IgnorePolicy)
		if err != nil {
			return err
		}
		results[i].Vulnerabilities = vulns
	}

	if err = report.WriteResults(conf.Format, conf.Output, conf.Severities, results, conf.Template, false); err != nil {
		return xerrors.Errorf("unable to write results: %w", err)
	}

	exit(conf, results)

	return nil
}

func initialize(conf *config.Config) error {
	// Initialize logger
	if err := log.InitLogger(conf.Debug, conf.Quiet); err != nil {
		return xerrors.Errorf("failed to initialize a logger: %w", err)
	}

	// Initialize config
	if err := conf.Init(); err != nil {
		return xerrors.Errorf("failed to initialize options: %w", err)
	}

	// configure cache dir
	utils.SetCacheDir(conf.CacheDir)
	log.Logger.Debugf("cache dir:  %s", utils.CacheDir())

	return nil
}

func initializeScanner(ctx context.Context, conf config.Config) (scanner.Scanner, func(), error) {
	remoteCache := cache.NewRemoteCache(cache.RemoteURL(conf.RemoteAddr), conf.CustomHeaders)

	// By default, apk commands are not analyzed.
	disabledAnalyzers := []analyzer.Type{analyzer.TypeApkCommand}
	if conf.ScanRemovedPkgs {
		disabledAnalyzers = []analyzer.Type{}
	}

	if conf.Input != "" {
		// Scan tar file
		s, err := initializeArchiveScanner(ctx, conf.Input, remoteCache,
			client.CustomHeaders(conf.CustomHeaders), client.RemoteURL(conf.RemoteAddr), conf.Timeout, disabledAnalyzers)
		if err != nil {
			return scanner.Scanner{}, nil, xerrors.Errorf("unable to initialize the archive scanner: %w", err)
		}
		return s, func() {}, nil
	}

	// Scan an image in Docker Engine or Docker Registry
	s, cleanup, err := initializeDockerScanner(ctx, conf.Target, remoteCache,
		client.CustomHeaders(conf.CustomHeaders), client.RemoteURL(conf.RemoteAddr), conf.Timeout, disabledAnalyzers)
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
