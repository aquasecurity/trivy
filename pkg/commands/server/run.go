package server

import (
	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/commands/operation"
	"github.com/aquasecurity/trivy/pkg/log"
	rpcServer "github.com/aquasecurity/trivy/pkg/rpc/server"
	"github.com/aquasecurity/trivy/pkg/utils"
)

// Run runs the scan
func Run(ctx *cli.Context) error {
	return run(NewConfig(ctx))
}

func run(c Config) (err error) {
	if err = log.InitLogger(c.Debug, c.Quiet); err != nil {
		return xerrors.Errorf("failed to initialize a logger: %w", err)
	}

	// initialize config
	if err = c.Init(); err != nil {
		return xerrors.Errorf("failed to initialize options: %w", err)
	}

	// configure cache dir
	utils.SetCacheDir(c.CacheDir)
	cache, err := operation.NewCache(c.CacheBackend)
	if err != nil {
		return xerrors.Errorf("server cache error: %w", err)
	}
	defer cache.Close()
	log.Logger.Debugf("cache dir:  %s", utils.CacheDir())

	if c.Reset {
		return cache.ClearDB()
	}

	// download the database file
	if err = operation.DownloadDB(c.AppVersion, c.CacheDir, true, false, c.SkipDBUpdate); err != nil {
		return err
	}

	if c.DownloadDBOnly {
		return nil
	}

	if err = db.Init(c.CacheDir); err != nil {
		return xerrors.Errorf("error in vulnerability DB initialize: %w", err)
	}

	server := rpcServer.NewServer(c.AppVersion, c.Listen, c.CacheDir, c.Token, c.TokenHeader)
	return server.ListenAndServe(cache)
}
