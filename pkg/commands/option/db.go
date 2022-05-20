package option

import (
	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/log"
)

// Allow for building trivy with DB updates completely disabled
var disableDBUpdates string

// DBOption holds the options for trivy DB
type DBOption struct {
	Reset          bool
	DownloadDBOnly bool
	SkipDBUpdate   bool
	Light          bool
	NoProgress     bool
	DBRepository   string
}

// NewDBOption is the factory method to return the DBOption
func NewDBOption(c *cli.Context) DBOption {
	skipDBUpdate := c.Bool("skip-db-update")
	if disableDBUpdates == "true" {
		skipDBUpdate = true
	}
	return DBOption{
		Reset:          c.Bool("reset"),
		DownloadDBOnly: c.Bool("download-db-only"),
		SkipDBUpdate:   skipDBUpdate,
		Light:          c.Bool("light"),
		NoProgress:     c.Bool("no-progress"),
		DBRepository:   c.String("db-repository"),
	}
}

// Init initialize the DBOption
func (c *DBOption) Init() (err error) {
	if c.SkipDBUpdate && c.DownloadDBOnly {
		return xerrors.New("--skip-db-update and --download-db-only options can not be specified both")
	}
	if c.Light {
		log.Logger.Warn("'--light' option is deprecated and will be removed. See also: https://github.com/aquasecurity/trivy/discussions/1649")
	}
	return nil
}
