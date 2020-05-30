package config

import (
	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"
)

type DBConfig struct {
	Reset          bool
	DownloadDBOnly bool
	SkipUpdate     bool
	Light          bool
	NoProgress     bool
}

func NewDBConfig(c *cli.Context) DBConfig {
	return DBConfig{
		Reset:          c.Bool("reset"),
		DownloadDBOnly: c.Bool("download-db-only"),
		SkipUpdate:     c.Bool("skip-update"),
		Light:          c.Bool("light"),
		NoProgress:     c.Bool("no-progress"),
	}
}

func (c *DBConfig) Init() (err error) {
	if c.SkipUpdate && c.DownloadDBOnly {
		return xerrors.New("--skip-update and --download-db-only options can not be specified both")
	}
	return nil
}
