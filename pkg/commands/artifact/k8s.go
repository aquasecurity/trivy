package artifact

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/urfave/cli/v2"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/log"
	pkgReport "github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"
)

// K8sRun runs scan on kubernetes cluster
func K8sRun(ctx *cli.Context) error {
	opt, err := initOption(ctx)
	if err != nil {
		return xerrors.Errorf("option error: %w", err)
	}

	// Disable the lock file scanning
	opt.DisabledAnalyzers = analyzer.TypeLockfiles

	if err = log.InitLogger(opt.Debug, true); err != nil {
		return err
	}

	cacheClient, err := initCache(opt)
	if err != nil {
		if errors.Is(err, errSkipScan) {
			return nil
		}
		return xerrors.Errorf("cache error: %w", err)
	}
	defer cacheClient.Close()

	// TODO(knqyf263): refactor
	// When scanning config files or running as client mode, it doesn't need to download the vulnerability database.
	if opt.RemoteAddr == "" && slices.Contains(opt.SecurityChecks, types.SecurityCheckVulnerability) {
		if err = initDB(opt); err != nil {
			if errors.Is(err, errSkipScan) {
				return nil
			}
			return xerrors.Errorf("DB error: %w", err)
		}
		defer db.Close()
	}

	scannerConfig, scannerOptions, err := initScannerConfig(ctx.Context, opt, cacheClient)
	if err != nil {
		return xerrors.Errorf("scanner config error: %w", err)
	}

	// TODO(starboard team): update however you want
	namespaces := []string{"kube-system", "default"}
	for _, ns := range namespaces {
		kinds := []string{"Deployment"}
		for _, kind := range kinds {
			names := []string{"app1", "app2"}
			for _, name := range names {
				images := []string{"alpine:3.15.0", "python:3.7-alpine"}

				// TODO: consider how to generate JSON
				for _, image := range images {
					report, err := scanImage(ctx.Context, image, scannerConfig, scannerOptions)
					if err != nil {
						return err
					}

					report, err = filter(ctx.Context, opt, report)
					if err != nil {
						return xerrors.Errorf("filter error: %w", err)
					}

					for i, res := range report.Results {
						target := fmt.Sprintf("%s/%s", image, res.Target)
						if res.Class == types.ClassOSPkg {
							target = res.Target
						}
						report.Results[i].Target = strings.Join([]string{ns, kind, name, target}, "/")
					}

					// TODO: consider how to display tables
					err = pkgReport.Write(report, pkgReport.Option{
						AppVersion:         opt.GlobalOption.AppVersion,
						Format:             opt.Format,
						Output:             opt.Output,
						Severities:         opt.Severities,
						OutputTemplate:     opt.Template,
						IncludeNonFailures: opt.IncludeNonFailures,
						Trace:              opt.Trace,
					})
					if err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func scanImage(ctx context.Context, imageName string, config ScannerConfig, opts types.ScanOptions) (types.Report, error) {
	config.Target = imageName
	s, cleanup, err := imageScanner(ctx, config)
	if err != nil {
		// TODO: should exit?
		log.Logger.Errorf("Unexpected error during scanning %s: %s", imageName, err)
		return types.Report{}, nil
	}
	defer cleanup()

	report, err := s.ScanArtifact(ctx, opts)
	if err != nil {
		return types.Report{}, xerrors.Errorf("image scan failed: %w", err)
	}
	return report, nil
}
