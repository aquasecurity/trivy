package standalone

import (
	"context"
	l "log"
	"os"

	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/internal/standalone/config"
	dbFile "github.com/aquasecurity/trivy/pkg/db"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/scanner"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/utils"
	"github.com/aquasecurity/trivy/pkg/vulnerability"
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
		return reset()
	}

	if c.ClearCache {
		return clearCache()
	}

	if err = db.Init(c.CacheDir); err != nil {
		return xerrors.Errorf("error in vulnerability DB initialize: %w", err)
	}

	// download the database file
	if err = downloadDB(c.AppVersion, c.CacheDir, c.Light, c.SkipUpdate); err != nil {
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

	results, err := scanner.ScanImage(c.ImageName, c.Input, scanOptions)
	if err != nil {
		return xerrors.Errorf("error in image scan: %w", err)
	}

	vulnClient := vulnerability.NewClient()
	for i := range results {
		results[i].Vulnerabilities = vulnClient.FillAndFilter(results[i].Vulnerabilities,
			c.Severities, c.IgnoreUnfixed, c.IgnoreFile, c.Light)
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

func reset() (err error) {
	log.Logger.Info("Resetting...")
	if err = cache.Clear(); err != nil {
		return xerrors.New("failed to remove image layer cache")
	}
	if err = os.RemoveAll(utils.CacheDir()); err != nil {
		return xerrors.New("failed to remove cache")
	}
	return nil
}

func clearCache() error {
	log.Logger.Info("Removing image caches...")
	if err := cache.Clear(); err != nil {
		return xerrors.New("failed to remove image layer cache")
	}
	return nil
}

func downloadDB(appVersion, cacheDir string, light, skipUpdate bool) error {
	client := dbFile.NewClient()
	ctx := context.Background()
	if err := client.Download(ctx, appVersion, cacheDir, light, skipUpdate); err != nil {
		return xerrors.Errorf("failed to download vulnerability DB: %w", err)
	}
	// for debug
	if err := showDBInfo(); err != nil {
		return xerrors.Errorf("failed to show database info")
	}
	return nil
}

func showDBInfo() error {
	metadata, err := db.Config{}.GetMetadata()
	if err != nil {
		return xerrors.Errorf("something wrong with DB: %w", err)
	}
	log.Logger.Debugf("DB Schema: %d, Type: %d, UpdatedAt: %s, NextUpdate: %s",
		metadata.Version, metadata.Type, metadata.UpdatedAt, metadata.NextUpdate)
	return nil
}
