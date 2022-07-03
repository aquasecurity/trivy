package flag

import (
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/samber/lo"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"
)

const (
	ResetFlag          = "reset"
	DownloadDBOnlyFlag = "download-db-only"
	SkipDBUpdateFlag   = "skip-db-update"
	LightFlag          = "light"
	NoProgressFlag     = "no-progress"
	DBRepositoryFlag   = "db-repository"

	defaultDBRepository = "ghcr.io/aquasecurity/trivy-db"
)

// DBFlags composes common printer flag structs used for commands requiring DB logic.
type DBFlags struct {
	Reset          *bool
	DownloadDBOnly *bool
	SkipDBUpdate   *bool
	NoProgress     *bool
	DBRepository   *string
	Light          *bool // deprecated
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
		Reset:          lo.ToPtr(false),
		DownloadDBOnly: lo.ToPtr(false),
		SkipDBUpdate:   lo.ToPtr(false),
		Light:          lo.ToPtr(false),
		NoProgress:     lo.ToPtr(false),
		DBRepository:   lo.ToPtr(defaultDBRepository),
	}
}

func (f *DBFlags) AddFlags(cmd *cobra.Command) {
	if f.Reset != nil {
		cmd.Flags().Bool(ResetFlag, *f.Reset, "remove all caches and database")
	}
	if f.DownloadDBOnly != nil {
		cmd.Flags().Bool(DownloadDBOnlyFlag, *f.DownloadDBOnly, "download/update vulnerability database but don't run a scan")
	}
	if f.SkipDBUpdate != nil {
		cmd.Flags().Bool(SkipDBUpdateFlag, *f.SkipDBUpdate, "skip updating vulnerability database")
	}
	if f.NoProgress != nil {
		cmd.Flags().Bool(NoProgressFlag, *f.NoProgress, "suppress progress bar")
	}
	if f.DBRepository != nil {
		cmd.Flags().String(DBRepositoryFlag, *f.DBRepository, "OCI repository to retrieve trivy-db from")
	}
	if f.Light != nil {
		cmd.Flags().Bool(LightFlag, *f.Light, "deprecated")
	}
}

func (f *DBFlags) ToOptions() (DBOptions, error) {
	skipDBUpdate := viper.GetBool(SkipDBUpdateFlag)
	downloadDBOnly := viper.GetBool(DownloadDBOnlyFlag)
	light := viper.GetBool(LightFlag)

	if skipDBUpdate && downloadDBOnly {
		return DBOptions{}, xerrors.New("--skip-db-update and --download-db-only options can not be specified both")
	}
	if light {
		log.Logger.Warn("'--light' option is deprecated and will be removed. See also: https://github.com/aquasecurity/trivy/discussions/1649")
	}

	return DBOptions{
		Reset:          viper.GetBool(ResetFlag),
		DownloadDBOnly: downloadDBOnly,
		SkipDBUpdate:   skipDBUpdate,
		Light:          light,
		NoProgress:     viper.GetBool(NoProgressFlag),
		DBRepository:   viper.GetString(DBRepositoryFlag),
	}, nil
}
