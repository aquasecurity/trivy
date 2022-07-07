package flag

import (
	"github.com/samber/lo"
	"github.com/spf13/cobra"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/log"
)

const defaultDBRepository = "ghcr.io/aquasecurity/trivy-db"

var (
	ResetFlag = Flag{
		Name:       "reset",
		ConfigName: "reset",
		Value:      false,
		Usage:      "remove all caches and database",
	}
	DownloadDBOnlyFlag = Flag{
		Name:       "download-db-only",
		ConfigName: "db.download-only",
		Value:      false,
		Usage:      "download/update vulnerability database but don't run a scan",
	}
	SkipDBUpdateFlag = Flag{
		Name:       "skip-db-update",
		ConfigName: "db.skip-update",
		Value:      false,
		Usage:      "skip updating vulnerability database",
	}
	NoProgressFlag = Flag{
		Name:       "no-progress",
		ConfigName: "db.no-progress",
		Value:      false,
		Usage:      "suppress progress bar",
	}
	DBRepositoryFlag = Flag{
		Name:       "db-repository",
		ConfigName: "db.repository",
		Value:      defaultDBRepository,
		Usage:      "OCI repository to retrieve trivy-db from\"",
	}
	LightFlag = Flag{
		Name:       "light",
		ConfigName: "db.light",
		Value:      false,
		Usage:      "deprecated",
	}
)

// DBFlags composes common printer flag structs used for commands requiring DB logic.
type DBFlags struct {
	Reset          *Flag
	DownloadDBOnly *Flag
	SkipDBUpdate   *Flag
	NoProgress     *Flag
	DBRepository   *Flag
	Light          *Flag // deprecated
}

type DBOptions struct {
	Reset          bool
	DownloadDBOnly bool
	SkipDBUpdate   bool
	NoProgress     bool
	DBRepository   string
	Light          bool // deprecated
}

// NewDBFlags returns a default DBFlags
func NewDBFlags() *DBFlags {
	return &DBFlags{
		Reset:          lo.ToPtr(ResetFlag),
		DownloadDBOnly: lo.ToPtr(DownloadDBOnlyFlag),
		SkipDBUpdate:   lo.ToPtr(SkipDBUpdateFlag),
		Light:          lo.ToPtr(LightFlag),
		NoProgress:     lo.ToPtr(NoProgressFlag),
		DBRepository:   lo.ToPtr(DBRepositoryFlag),
	}
}

func (f *DBFlags) flags() []*Flag {
	return []*Flag{f.Reset, f.DownloadDBOnly, f.SkipDBUpdate, f.NoProgress, f.DBRepository, f.Light}
}

func (f *DBFlags) AddFlags(cmd *cobra.Command) {
	for _, flag := range f.flags() {
		addFlag(cmd, flag)
	}
}

func (f *DBFlags) Bind(cmd *cobra.Command) error {
	for _, flag := range f.flags() {
		if err := bind(cmd, flag); err != nil {
			return err
		}
	}
	return nil
}

func (f *DBFlags) ToOptions() (DBOptions, error) {
	skipDBUpdate := getBool(f.SkipDBUpdate)
	downloadDBOnly := getBool(f.DownloadDBOnly)
	light := getBool(f.Light)

	if downloadDBOnly && skipDBUpdate {
		return DBOptions{}, xerrors.New("--skip-db-update and --download-db-only options can not be specified both")
	}
	if light {
		log.Logger.Warn("'--light' option is deprecated and will be removed. See also: https://github.com/aquasecurity/trivy/discussions/1649")
	}

	return DBOptions{
		Reset:          getBool(f.Reset),
		DownloadDBOnly: downloadDBOnly,
		SkipDBUpdate:   skipDBUpdate,
		Light:          light,
		NoProgress:     getBool(f.NoProgress),
		DBRepository:   getString(f.DBRepository),
	}, nil
}
