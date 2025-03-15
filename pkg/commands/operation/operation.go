package operation

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/db"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/misconf"
	"github.com/aquasecurity/trivy/pkg/policy"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/vex"
	"github.com/aquasecurity/trivy/pkg/vex/repo"
)

var mu sync.Mutex

// DownloadDB downloads the DB
func DownloadDB(ctx context.Context, appVersion, cacheDir string, dbRepositories []name.Reference, quiet, skipUpdate bool,
	opt ftypes.RegistryOptions) error {
	mu.Lock()
	defer mu.Unlock()

	ctx = log.WithContextPrefix(ctx, log.PrefixVulnerabilityDB)
	dbDir := db.Dir(cacheDir)
	client := db.NewClient(dbDir, quiet, db.WithDBRepository(dbRepositories))
	needsUpdate, err := client.NeedsUpdate(ctx, appVersion, skipUpdate)
	if err != nil {
		return xerrors.Errorf("database error: %w", err)
	}

	if needsUpdate {
		log.InfoContext(ctx, "Need to update DB")
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

func DownloadVEXRepositories(ctx context.Context, opts flag.Options) error {
	ctx = log.WithContextPrefix(ctx, "vex")
	if opts.SkipVEXRepoUpdate {
		log.InfoContext(ctx, "Skipping VEX repository update")
		return nil
	}

	mu.Lock()
	defer mu.Unlock()

	// Download VEX repositories only if `--vex repo` is passed.
	_, enabled := lo.Find(opts.VEXSources, func(src vex.Source) bool {
		return src.Type == vex.TypeRepository
	})
	if !enabled {
		return nil
	}

	err := repo.NewManager(opts.CacheDir).DownloadRepositories(ctx, nil, repo.Options{
		Insecure: opts.Insecure,
	})
	if err != nil {
		return xerrors.Errorf("failed to download vex repositories: %w", err)
	}

	return nil

}

// InitBuiltinChecks downloads the built-in policies and loads them
func InitBuiltinChecks(ctx context.Context, client *policy.Client, skipUpdate bool, registryOpts ftypes.RegistryOptions) (string, error) {
	mu.Lock()
	defer mu.Unlock()
	var err error

	if skipUpdate {
		log.Info("No downloadable checks were loaded as --skip-check-update is enabled, loading from existing cache...")

		path := client.LoadBuiltinChecks()
		_, _, err := misconf.CheckPathExists(path)
		if err != nil {
			msg := fmt.Sprintf("Failed to load existing cache, err: %s falling back to embedded checks...", err.Error())
			log.Error(msg)
			return "", xerrors.New(msg)
		}
		return path, nil
	}

	needsUpdate := false
	needsUpdate, err = client.NeedsUpdate(ctx, registryOpts)
	if err != nil {
		return "", xerrors.Errorf("unable to check if built-in policies need to be updated: %w", err)
	}

	if needsUpdate {
		log.InfoContext(ctx, "Need to update the checks bundle")
		log.InfoContext(ctx, "Downloading the checks bundle...")
		if err = client.DownloadBuiltinChecks(ctx, registryOpts); err != nil {
			return "", xerrors.Errorf("failed to download checks bundle: %w", err)
		}
	}

	return client.LoadBuiltinChecks(), nil
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
