package server

import (
	"context"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/commands/operation"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/module"
	rpcServer "github.com/aquasecurity/trivy/pkg/rpc/server"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

// Run runs the scan
func Run(ctx context.Context, opts flag.Options) (err error) {
	log.InitLogger(opts.Debug, opts.Quiet)

	// configure cache dir
	fsutils.SetCacheDir(opts.CacheDir)
	cacheClient, err := cache.NewClient(opts.CacheOptions.CacheBackendOptions)
	if err != nil {
		return xerrors.Errorf("server cache error: %w", err)
	}
	defer cacheClient.Close()
	log.Debug("Cache", log.String("dir", fsutils.CacheDir()))

	if opts.Reset {
		return cacheClient.ClearDB()
	}

	// download the database file
	if err = operation.DownloadDB(ctx, opts.AppVersion, opts.CacheDir, opts.DBRepository,
		true, opts.SkipDBUpdate, opts.RegistryOpts()); err != nil {
		return err
	}

	if opts.DownloadDBOnly {
		return nil
	}

	if err = db.Init(opts.CacheDir); err != nil {
		return xerrors.Errorf("error in vulnerability DB initialize: %w", err)
	}

	// Initialize WASM modules
	m, err := module.NewManager(ctx, module.Options{
		Dir:            opts.ModuleDir,
		EnabledModules: opts.EnabledModules,
	})
	if err != nil {
		return xerrors.Errorf("WASM module error: %w", err)
	}
	m.Register()

	server := rpcServer.NewServer(opts.AppVersion, opts.Listen, opts.CacheDir, opts.Token, opts.TokenHeader,
		opts.DBRepository, opts.RegistryOpts())
	return server.ListenAndServe(ctx, cacheClient, opts.SkipDBUpdate)
}
