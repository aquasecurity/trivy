package operation

import (
	"context"
	"sync"

	"github.com/google/go-containerregistry/pkg/name"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/db"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/policy"
	"github.com/aquasecurity/trivy/pkg/types"
)

var mu sync.Mutex

// DownloadDB downloads the DB
func DownloadDB(ctx context.Context, appVersion, cacheDir string, dbRepository name.Reference, quiet, skipUpdate bool,
	opt ftypes.RegistryOptions) error {
	mu.Lock()
	defer mu.Unlock()

	dbDir := db.Dir(cacheDir)
	client := db.NewClient(dbDir, quiet, db.WithDBRepository(dbRepository))
	needsUpdate, err := client.NeedsUpdate(ctx, appVersion, skipUpdate)
	if err != nil {
		return xerrors.Errorf("database error: %w", err)
	}

	if needsUpdate {
		log.Info("Need to update DB")
		log.Info("Downloading DB...", log.String("repository", dbRepository.String()))
		if err = client.Download(ctx, dbDir, opt); err != nil {
			return xerrors.Errorf("failed to download vulnerability DB: %w", err)
		}
	}

	// for debug
	if err = client.ShowInfo(); err != nil {
		return xerrors.Errorf("failed to show database info: %w", err)
	}
	return nil
}

// InitBuiltinPolicies downloads the built-in policies and loads them
func InitBuiltinPolicies(ctx context.Context, cacheDir string, quiet, skipUpdate bool, checkBundleRepository string, registryOpts ftypes.RegistryOptions) ([]string, error) {
	mu.Lock()
	defer mu.Unlock()

	client, err := policy.NewClient(cacheDir, quiet, checkBundleRepository)
	if err != nil {
		return nil, xerrors.Errorf("check client error: %w", err)
	}

	needsUpdate := false
	if !skipUpdate {
		needsUpdate, err = client.NeedsUpdate(ctx, registryOpts)
		if err != nil {
			return nil, xerrors.Errorf("unable to check if built-in policies need to be updated: %w", err)
		}
	}

	if needsUpdate {
		log.Info("Need to update the built-in policies")
		log.Info("Downloading the built-in policies...")
		if err = client.DownloadBuiltinPolicies(ctx, registryOpts); err != nil {
			return nil, xerrors.Errorf("failed to download built-in policies: %w", err)
		}
	}

	policyPaths, err := client.LoadBuiltinPolicies()
	if err != nil {
		if skipUpdate {
			msg := "No downloadable policies were loaded as --skip-check-update is enabled"
			log.Info(msg)
			return nil, xerrors.Errorf(msg)
		}
		return nil, xerrors.Errorf("check load error: %w", err)
	}
	return policyPaths, nil
}

func Exit(opts flag.Options, failedResults bool, m types.Metadata) error {
	if opts.ExitOnEOL != 0 && m.OS != nil && m.OS.Eosl {
		log.Error("Detected EOL OS", log.String("family", string(m.OS.Family)),
			log.String("version", m.OS.Name))
		return &types.ExitError{Code: opts.ExitOnEOL}
	}

	if opts.ExitCode != 0 && failedResults {
		return &types.ExitError{Code: opts.ExitCode}
	}
	return nil
}
