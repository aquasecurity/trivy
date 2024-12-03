package flag

import (
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/db"
	"github.com/aquasecurity/trivy/pkg/javadb"
	"github.com/aquasecurity/trivy/pkg/log"
)

var (
	// Deprecated
	ResetFlag = Flag[bool]{
		Name:       "reset",
		ConfigName: "reset",
		Usage:      "remove all caches and database",
		Removed:    `Use "trivy clean --all" instead.`,
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
	DBRepositoryFlag = Flag[[]string]{
		Name:       "db-repository",
		ConfigName: "db.repository",
		Default:    []string{db.DefaultGCRRepository, db.DefaultGHCRRepository},
		Usage:      "OCI repository(ies) to retrieve trivy-db in order of priority",
	}
	JavaDBRepositoryFlag = Flag[[]string]{
		Name:       "java-db-repository",
		ConfigName: "db.java-repository",
		Default:    []string{javadb.DefaultGCRRepository, javadb.DefaultGHCRRepository},
		Usage:      "OCI repository(ies) to retrieve trivy-java-db in order of priority",
	}
	LightFlag = Flag[bool]{
		Name:       "light",
		ConfigName: "db.light",
		Usage:      "deprecated",
		Deprecated: `This flag is ignored.`,
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
	DBRepositories     *Flag[[]string]
	JavaDBRepositories *Flag[[]string]
	Light              *Flag[bool] // deprecated
}

type DBOptions struct {
	Reset              bool
	DownloadDBOnly     bool
	SkipDBUpdate       bool
	DownloadJavaDBOnly bool
	SkipJavaDBUpdate   bool
	NoProgress         bool
	DBRepositories     []name.Reference
	JavaDBRepositories []name.Reference
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
		DBRepositories:     DBRepositoryFlag.Clone(),
		JavaDBRepositories: JavaDBRepositoryFlag.Clone(),
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
		f.DBRepositories,
		f.JavaDBRepositories,
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

	if downloadDBOnly && downloadJavaDBOnly {
		return DBOptions{}, xerrors.New("--download-db-only and --download-java-db-only options can not be specified both")
	}
	if downloadDBOnly && skipDBUpdate {
		return DBOptions{}, xerrors.New("--skip-db-update and --download-db-only options can not be specified both")
	}
	if downloadJavaDBOnly && skipJavaDBUpdate {
		return DBOptions{}, xerrors.New("--skip-java-db-update and --download-java-db-only options can not be specified both")
	}

	var dbRepositories, javaDBRepositories []name.Reference
	for _, repo := range f.DBRepositories.Value() {
		ref, err := parseRepository(repo, db.SchemaVersion)
		if err != nil {
			return DBOptions{}, xerrors.Errorf("invalid DB repository: %w", err)
		}
		dbRepositories = append(dbRepositories, ref)
	}

	for _, repo := range f.JavaDBRepositories.Value() {
		ref, err := parseRepository(repo, javadb.SchemaVersion)
		if err != nil {
			return DBOptions{}, xerrors.Errorf("invalid javadb repository: %w", err)
		}
		javaDBRepositories = append(javaDBRepositories, ref)
	}

	return DBOptions{
		Reset:              f.Reset.Value(),
		DownloadDBOnly:     downloadDBOnly,
		SkipDBUpdate:       skipDBUpdate,
		DownloadJavaDBOnly: downloadJavaDBOnly,
		SkipJavaDBUpdate:   skipJavaDBUpdate,
		NoProgress:         f.NoProgress.Value(),
		DBRepositories:     dbRepositories,
		JavaDBRepositories: javaDBRepositories,
	}, nil
}

func parseRepository(repo string, dbSchemaVersion int) (name.Reference, error) {
	dbRepository, err := name.ParseReference(repo, name.WithDefaultTag(""))
	if err != nil {
		return nil, err
	}

	// Add the schema version if the tag is not specified for backward compatibility.
	t, ok := dbRepository.(name.Tag)
	if !ok || t.TagStr() != "" {
		return dbRepository, nil
	}

	dbRepository = t.Tag(fmt.Sprint(dbSchemaVersion))
	log.Info("Adding schema version to the DB repository for backward compatibility",
		log.String("repository", dbRepository.String()))

	return dbRepository, nil
}
