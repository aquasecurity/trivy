package server

import (
	"github.com/urfave/cli"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/internal/operation"
	"github.com/aquasecurity/trivy/internal/server/config"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/rpc/server"
	"github.com/aquasecurity/trivy/pkg/utils"
)

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
	cacheClient, err := cache.New(c.CacheDir)
	if err != nil {
		return xerrors.Errorf("unable to initialize cache client: %w", err)
	}
	cacheOperation := operation.NewCache(cacheClient)
	log.Logger.Debugf("cache dir:  %s", utils.CacheDir())

	if c.Reset {
		return cacheOperation.ClearAll()
	}

	if err = db.Init(c.CacheDir); err != nil {
		return xerrors.Errorf("error in vulnerability DB initialize: %w", err)
	}

	// download the database file
	if err = operation.DownloadDB(c.AppVersion, c.CacheDir, true, false, c.SkipUpdate); err != nil {
		return err
	}

	if c.DownloadDBOnly {
		return nil
	}

	return server.ListenAndServe(c.Listen, c)
}
