package flag

import (
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/log"
)

const defaultDBRepository = "ghcr.io/aquasecurity/trivy-db"
const defaultJavaDBRepository = "ghcr.io/aquasecurity/trivy-java-db"

var (
	ResetFlag = Flag{
		Name:       "reset",
		ConfigName: "reset",
		Default:    false,
		Usage:      "remove all caches and database",
	}
	DownloadDBOnlyFlag = Flag{
		Name:       "download-db-only",
		ConfigName: "db.download-only",
		Default:    false,
		Usage:      "download/update vulnerability database but don't run a scan",
	}
	SkipDBUpdateFlag = Flag{
		Name:       "skip-db-update",
		ConfigName: "db.skip-update",
		Default:    false,
		Usage:      "skip updating vulnerability database",
		Aliases: []Alias{
			{
				Name:       "skip-update",
				Deprecated: true, // --skip-update was renamed to --skip-db-update
			},
		},
	}
	DownloadJavaDBOnlyFlag = Flag{
		Name:       "download-java-db-only",
		ConfigName: "db.download-java-only",
		Default:    false,
		Usage:      "download/update Java index database but don't run a scan",
	}
	SkipJavaDBUpdateFlag = Flag{
		Name:       "skip-java-db-update",
		ConfigName: "db.java-skip-update",
		Default:    false,
		Usage:      "skip updating Java index database",
	}
	NoProgressFlag = Flag{
		Name:       "no-progress",
		ConfigName: "db.no-progress",
		Default:    false,
		Usage:      "suppress progress bar",
	}
	DBRepositoryFlag = Flag{
		Name:       "db-repository",
		ConfigName: "db.repository",
		Default:    defaultDBRepository,
		Usage:      "OCI repository to retrieve trivy-db from",
	}
	JavaDBRepositoryFlag = Flag{
		Name:       "java-db-repository",
		ConfigName: "db.java-repository",
		Default:    defaultJavaDBRepository,
		Usage:      "OCI repository to retrieve trivy-java-db from",
	}
	LightFlag = Flag{
		Name:       "light",
		ConfigName: "db.light",
		Default:    false,
		Usage:      "deprecated",
		Deprecated: true,
	}
)

// DBFlagGroup composes common printer flag structs used for commands requiring DB logic.
type DBFlagGroup struct {
	Reset              *Flag
	DownloadDBOnly     *Flag
	SkipDBUpdate       *Flag
	DownloadJavaDBOnly *Flag
	SkipJavaDBUpdate   *Flag
	NoProgress         *Flag
	DBRepository       *Flag
	JavaDBRepository   *Flag
	Light              *Flag // deprecated
}

type DBOptions struct {
	Reset              bool
	DownloadDBOnly     bool
	SkipDBUpdate       bool
	DownloadJavaDBOnly bool
	SkipJavaDBUpdate   bool
	NoProgress         bool
	DBRepository       string
	JavaDBRepository   string
	Light              bool // deprecated
}

// NewDBFlagGroup returns a default DBFlagGroup
func NewDBFlagGroup() *DBFlagGroup {
	return &DBFlagGroup{
		Reset:              &ResetFlag,
		DownloadDBOnly:     &DownloadDBOnlyFlag,
		SkipDBUpdate:       &SkipDBUpdateFlag,
		DownloadJavaDBOnly: &DownloadJavaDBOnlyFlag,
		SkipJavaDBUpdate:   &SkipJavaDBUpdateFlag,
		Light:              &LightFlag,
		NoProgress:         &NoProgressFlag,
		DBRepository:       &DBRepositoryFlag,
		JavaDBRepository:   &JavaDBRepositoryFlag,
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
		f.DownloadJavaDBOnly,
		f.SkipJavaDBUpdate,
		f.NoProgress,
		f.DBRepository,
		f.JavaDBRepository,
		f.Light,
	}
}

func (f *DBFlagGroup) ToOptions() (DBOptions, error) {
	skipDBUpdate := getBool(f.SkipDBUpdate)
	skipJavaDBUpdate := getBool(f.SkipJavaDBUpdate)
	downloadDBOnly := getBool(f.DownloadDBOnly)
	downloadJavaDBOnly := getBool(f.DownloadJavaDBOnly)
	light := getBool(f.Light)

	if downloadDBOnly && skipDBUpdate {
		return DBOptions{}, xerrors.New("--skip-db-update and --download-db-only options can not be specified both")
	}
	if downloadJavaDBOnly && skipJavaDBUpdate {
		return DBOptions{}, xerrors.New("--skip-java-db-update and --download-java-db-only options can not be specified both")
	}
	if light {
		log.Logger.Warn("'--light' option is deprecated and will be removed. See also: https://github.com/aquasecurity/trivy/discussions/1649")
	}

	return DBOptions{
		Reset:              getBool(f.Reset),
		DownloadDBOnly:     downloadDBOnly,
		SkipDBUpdate:       skipDBUpdate,
		DownloadJavaDBOnly: downloadJavaDBOnly,
		SkipJavaDBUpdate:   skipJavaDBUpdate,
		Light:              light,
		NoProgress:         getBool(f.NoProgress),
		DBRepository:       getString(f.DBRepository),
		JavaDBRepository:   getString(f.JavaDBRepository),
	}, nil
}
