package flag

import (
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/log"
)

const defaultDBRepository = "ghcr.io/aquasecurity/trivy-db:2"
const defaultJavaDBRepository = "ghcr.io/aquasecurity/trivy-java-db:1"

var (
	ResetFlag = Flag[bool]{
		Name:       "reset",
		ConfigName: "reset",
		Usage:      "remove all caches and database",
	}
	DownloadDBOnlyFlag = Flag[bool]{
		Name:       "download-db-only",
		ConfigName: "db.download-only",
		Usage:      "download/update vulnerability database but don't run a scan",
	}
	SkipDBUpdateFlag = Flag[bool]{
		Name:       "skip-db-update",
		ConfigName: "db.skip-update",
		Usage:      "skip updating vulnerability database",
		Aliases: []Alias{
			{
				Name:       "skip-update",
				Deprecated: true, // --skip-update was renamed to --skip-db-update
			},
		},
	}
	DownloadJavaDBOnlyFlag = Flag[bool]{
		Name:       "download-java-db-only",
		ConfigName: "db.download-java-only",
		Usage:      "download/update Java index database but don't run a scan",
	}
	SkipJavaDBUpdateFlag = Flag[bool]{
		Name:       "skip-java-db-update",
		ConfigName: "db.java-skip-update",
		Usage:      "skip updating Java index database",
	}
	NoProgressFlag = Flag[bool]{
		Name:       "no-progress",
		ConfigName: "db.no-progress",
		Usage:      "suppress progress bar",
	}
	DBRepositoryFlag = Flag[string]{
		Name:       "db-repository",
		ConfigName: "db.repository",
		Default:    defaultDBRepository,
		Usage:      "OCI repository to retrieve trivy-db from",
	}
	JavaDBRepositoryFlag = Flag[string]{
		Name:       "java-db-repository",
		ConfigName: "db.java-repository",
		Default:    defaultJavaDBRepository,
		Usage:      "OCI repository to retrieve trivy-java-db from",
	}
	LightFlag = Flag[bool]{
		Name:       "light",
		ConfigName: "db.light",
		Usage:      "deprecated",
		Deprecated: true,
	}
)

// DBFlagGroup composes common printer flag structs used for commands requiring DB logic.
type DBFlagGroup struct {
	Reset              *Flag[bool]
	DownloadDBOnly     *Flag[bool]
	SkipDBUpdate       *Flag[bool]
	DownloadJavaDBOnly *Flag[bool]
	SkipJavaDBUpdate   *Flag[bool]
	NoProgress         *Flag[bool]
	DBRepository       *Flag[string]
	JavaDBRepository   *Flag[string]
	Light              *Flag[bool] // deprecated
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
		Reset:              ResetFlag.Clone(),
		DownloadDBOnly:     DownloadDBOnlyFlag.Clone(),
		SkipDBUpdate:       SkipDBUpdateFlag.Clone(),
		DownloadJavaDBOnly: DownloadJavaDBOnlyFlag.Clone(),
		SkipJavaDBUpdate:   SkipJavaDBUpdateFlag.Clone(),
		Light:              LightFlag.Clone(),
		NoProgress:         NoProgressFlag.Clone(),
		DBRepository:       DBRepositoryFlag.Clone(),
		JavaDBRepository:   JavaDBRepositoryFlag.Clone(),
	}
}

func (f *DBFlagGroup) Name() string {
	return "DB"
}

func (f *DBFlagGroup) Flags() []Flagger {
	return []Flagger{
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
	if err := parseFlags(f); err != nil {
		return DBOptions{}, err
	}

	skipDBUpdate := f.SkipDBUpdate.Value()
	skipJavaDBUpdate := f.SkipJavaDBUpdate.Value()
	downloadDBOnly := f.DownloadDBOnly.Value()
	downloadJavaDBOnly := f.DownloadJavaDBOnly.Value()
	light := f.Light.Value()

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
		Reset:              f.Reset.Value(),
		DownloadDBOnly:     downloadDBOnly,
		SkipDBUpdate:       skipDBUpdate,
		DownloadJavaDBOnly: downloadJavaDBOnly,
		SkipJavaDBUpdate:   skipJavaDBUpdate,
		Light:              light,
		NoProgress:         f.NoProgress.Value(),
		DBRepository:       f.DBRepository.Value(),
		JavaDBRepository:   f.JavaDBRepository.Value(),
	}, nil
}
