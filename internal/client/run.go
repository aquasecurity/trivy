package client

import (
	"context"
	"os"

	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/internal/client/config"
	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/rpc/client"
	"github.com/aquasecurity/trivy/pkg/scanner"
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
		log.Logger.Warn("A client doesn't have image cache")
		return nil
	}

	var scanner scanner.Scanner
	ctx := context.Background()
	remoteCache := cache.NewRemoteCache(cache.RemoteURL(c.RemoteAddr), c.CustomHeaders)

	cleanup := func() {}
	if c.Input != "" {
		// scan tar file
		scanner, err = initializeArchiveScanner(ctx, c.Input, remoteCache,
			client.CustomHeaders(c.CustomHeaders), client.RemoteURL(c.RemoteAddr), c.Timeout)
		if err != nil {
			return xerrors.Errorf("unable to initialize the archive scanner: %w", err)
		}
	} else {
		// scan an image in Docker Engine or Docker Registry
		scanner, cleanup, err = initializeDockerScanner(ctx, c.ImageName, remoteCache,
			client.CustomHeaders(c.CustomHeaders), client.RemoteURL(c.RemoteAddr), c.Timeout)
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
