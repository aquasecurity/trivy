package server

import (
	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/internal/operation"
	"github.com/aquasecurity/trivy/internal/server/config"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/rpc/server"
	"github.com/aquasecurity/trivy/pkg/utils"
)

// Run runs the scan
func Run(ctx *cli.Context) error {
	return run(config.New(ctx))
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

	fsCache, err := cache.NewFSCache(utils.CacheDir())
	if err != nil {
		return xerrors.Errorf("unable to initialize cache: %w", err)
	}

	// server doesn't have image cache
	cacheOperation := operation.NewCache(fsCache)
	if c.Reset {
		return cacheOperation.ClearDB()
	}

	// download the database file
	if err = operation.DownloadDB(c.AppVersion, c.CacheDir, true, false, c.SkipUpdate); err != nil {
		return err
	}

	if c.DownloadDBOnly {
		return nil
	}

	if err = db.Init(c.CacheDir); err != nil {
		return xerrors.Errorf("error in vulnerability DB initialize: %w", err)
	}

	return server.ListenAndServe(c, fsCache)
}
