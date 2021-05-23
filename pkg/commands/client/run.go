package client

import (
	"context"
	"os"

	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config"
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
	opt, err := NewOption(cliCtx)
	if err != nil {
		return xerrors.Errorf("option error: %w", err)
	}

	ctx, cancel := context.WithTimeout(cliCtx.Context, opt.Timeout)
	defer cancel()

	err = runWithTimeout(ctx, opt)
	if xerrors.Is(err, context.DeadlineExceeded) {
		log.Logger.Warn("Increase --timeout value")
	}
	return err
}

func runWithTimeout(ctx context.Context, opt Option) error {
	if err := initialize(&opt); err != nil {
		return xerrors.Errorf("initialize error: %w", err)
	}

	if opt.ClearCache {
		log.Logger.Warn("A client doesn't have image cache")
		return nil
	}

	s, cleanup, err := initializeScanner(ctx, opt)
	if err != nil {
		return xerrors.Errorf("scanner initialize error: %w", err)
	}
	defer cleanup()

	scanOptions := types.ScanOptions{
		VulnType:            opt.VulnType,
		SecurityChecks:      opt.SecurityChecks,
		ScanRemovedPackages: opt.ScanRemovedPkgs,
	}
	log.Logger.Debugf("Vulnerability type:  %s", scanOptions.VulnType)

	results, err := s.ScanArtifact(ctx, scanOptions)
	if err != nil {
		return xerrors.Errorf("error in image scan: %w", err)
	}

	resultClient := initializeResultClient()
	for i := range results {
		vulns, err := resultClient.Filter(ctx, results[i].Vulnerabilities,
			opt.Severities, opt.IgnoreUnfixed, opt.IgnoreFile, opt.IgnorePolicy)
		if err != nil {
			return xerrors.Errorf("filter error: %w", err)
		}
		results[i].Vulnerabilities = vulns
	}

	if err = report.WriteResults(opt.Format, opt.Output, opt.Severities, results, opt.Template, false); err != nil {
		return xerrors.Errorf("unable to write results: %w", err)
	}

	exit(opt, results)

	return nil
}

func initialize(opt *Option) error {
	// Initialize logger
	if err := log.InitLogger(opt.Debug, opt.Quiet); err != nil {
		return xerrors.Errorf("failed to initialize a logger: %w", err)
	}

	// Initialize options
	if err := opt.Init(); err != nil {
		return xerrors.Errorf("failed to initialize options: %w", err)
	}

	// configure cache dir
	utils.SetCacheDir(opt.CacheDir)
	log.Logger.Debugf("cache dir:  %s", utils.CacheDir())

	return nil
}

func initializeScanner(ctx context.Context, opt Option) (scanner.Scanner, func(), error) {
	remoteCache := cache.NewRemoteCache(cache.RemoteURL(opt.RemoteAddr), opt.CustomHeaders)

	// By default, apk commands are not analyzed.
	disabledAnalyzers := []analyzer.Type{analyzer.TypeApkCommand}
	if opt.ScanRemovedPkgs {
		disabledAnalyzers = []analyzer.Type{}
	}

	// TODO: fix the scanner option and enable config analyzers once we finalize the specification of config scanning.
	configScannerOptions := config.ScannerOption{}
	disabledAnalyzers = append(disabledAnalyzers, analyzer.TypeYaml, analyzer.TypeTOML, analyzer.TypeJSON,
		analyzer.TypeDockerfile, analyzer.TypeHCL)

	if opt.Input != "" {
		// Scan tar file
		s, err := initializeArchiveScanner(ctx, opt.Input, remoteCache, client.CustomHeaders(opt.CustomHeaders),
			client.RemoteURL(opt.RemoteAddr), opt.Timeout, disabledAnalyzers, configScannerOptions)
		if err != nil {
			return scanner.Scanner{}, nil, xerrors.Errorf("unable to initialize the archive scanner: %w", err)
		}
		return s, func() {}, nil
	}

	// Scan an image in Docker Engine or Docker Registry
	s, cleanup, err := initializeDockerScanner(ctx, opt.Target, remoteCache, client.CustomHeaders(opt.CustomHeaders),
		client.RemoteURL(opt.RemoteAddr), opt.Timeout, disabledAnalyzers, configScannerOptions)
	if err != nil {
		return scanner.Scanner{}, nil, xerrors.Errorf("unable to initialize the docker scanner: %w", err)
	}

	return s, cleanup, nil
}

func exit(c Option, results report.Results) {
	if c.ExitCode != 0 {
		for _, result := range results {
			if len(result.Vulnerabilities) > 0 {
				os.Exit(c.ExitCode)
			}
		}
	}
}
