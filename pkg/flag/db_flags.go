package flag

import (
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
		Aliases: []Alias{
			{
				Name:       "skip-update",
				Deprecated: true, // --security-update was renamed to --skip-db-update
			},
		},
	}
	SkipJavaDBUpdateFlag = Flag{
		Name:       "skip-java-db-update",
		ConfigName: "db.java-skip-update",
		Value:      false,
		Usage:      "skip updating java indexes database",
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
		Usage:      "OCI repository to retrieve trivy-db from",
	}
	LightFlag = Flag{
		Name:       "light",
		ConfigName: "db.light",
		Value:      false,
		Usage:      "deprecated",
		Deprecated: true,
	}
)

// DBFlagGroup composes common printer flag structs used for commands requiring DB logic.
type DBFlagGroup struct {
	Reset            *Flag
	DownloadDBOnly   *Flag
	SkipDBUpdate     *Flag
	SkipJavaDBUpdate *Flag
	NoProgress       *Flag
	DBRepository     *Flag
	Light            *Flag // deprecated
}

type DBOptions struct {
	Reset            bool
	DownloadDBOnly   bool
	SkipDBUpdate     bool
	SkipJavaDBUpdate bool
	NoProgress       bool
	DBRepository     string
	Light            bool // deprecated
}

// NewDBFlagGroup returns a default DBFlagGroup
func NewDBFlagGroup() *DBFlagGroup {
	return &DBFlagGroup{
		Reset:            &ResetFlag,
		DownloadDBOnly:   &DownloadDBOnlyFlag,
		SkipDBUpdate:     &SkipDBUpdateFlag,
		SkipJavaDBUpdate: &SkipJavaDBUpdateFlag,
		Light:            &LightFlag,
		NoProgress:       &NoProgressFlag,
		DBRepository:     &DBRepositoryFlag,
	}
}

func (f *DBFlagGroup) Name() string {
	return "DB"
}

func (f *DBFlagGroup) Flags() []*Flag {
	return []*Flag{
		f.Reset,
		f.DownloadDBOnly,
		f.SkipDBUpdate,
		f.SkipJavaDBUpdate,
		f.NoProgress,
		f.DBRepository,
		f.Light,
	}
}

func (f *DBFlagGroup) ToOptions() (DBOptions, error) {
	skipDBUpdate := getBool(f.SkipDBUpdate)
	skipJavaDBUpdate := getBool(f.SkipJavaDBUpdate)
	downloadDBOnly := getBool(f.DownloadDBOnly)
	light := getBool(f.Light)

	if downloadDBOnly && skipDBUpdate {
		return DBOptions{}, xerrors.New("--skip-db-update and --download-db-only options can not be specified both")
	}
	if light {
		log.Logger.Warn("'--light' option is deprecated and will be removed. See also: https://github.com/aquasecurity/trivy/discussions/1649")
	}

	return DBOptions{
		Reset:            getBool(f.Reset),
		DownloadDBOnly:   downloadDBOnly,
		SkipDBUpdate:     skipDBUpdate,
		SkipJavaDBUpdate: skipJavaDBUpdate,
		Light:            light,
		NoProgress:       getBool(f.NoProgress),
		DBRepository:     getString(f.DBRepository),
	}, nil
}
