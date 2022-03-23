package artifact

import (
	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/commands/option"
)

// Option holds the artifact options
type Option struct {
	option.GlobalOption
	option.ArtifactOption
	option.DBOption
	option.ImageOption
	option.ReportOption
	option.CacheOption
	option.ConfigOption
	option.RemoteOption
	option.SbomOption

	// We don't want to allow disabled analyzers to be passed by users,
	// but it differs depending on scanning modes.
	DisabledAnalyzers []analyzer.Type
}

// NewOption is the factory method to return options
func NewOption(c *cli.Context) (Option, error) {
	gc, err := option.NewGlobalOption(c)
	if err != nil {
		return Option{}, xerrors.Errorf("failed to initialize global options: %w", err)
	}

	return Option{
		GlobalOption:   gc,
		ArtifactOption: option.NewArtifactOption(c),
		DBOption:       option.NewDBOption(c),
		ImageOption:    option.NewImageOption(c),
		ReportOption:   option.NewReportOption(c),
		CacheOption:    option.NewCacheOption(c),
		ConfigOption:   option.NewConfigOption(c),
		RemoteOption:   option.NewRemoteOption(c),
		SbomOption:     option.NewSbomOption(c),
	}, nil
}

// Init initializes the artifact options
func (c *Option) Init() error {
	if err := c.initPreScanOptions(); err != nil {
		return err
	}

	// --clear-cache, --download-db-only and --reset don't conduct the scan
	if c.skipScan() {
		return nil
	}

	if err := c.ArtifactOption.Init(c.Context, c.Logger); err != nil {
		return err
	}
	return nil
}

func (c *Option) initPreScanOptions() error {
	if err := c.ReportOption.Init(c.Context.App.Writer, c.Logger); err != nil {
		return err
	}
	if err := c.DBOption.Init(); err != nil {
		return err
	}
	if err := c.CacheOption.Init(); err != nil {
		return err
	}
	if err := c.SbomOption.Init(c.Context, c.Logger); err != nil {
		return err
	}
	c.RemoteOption.Init(c.Logger)
	return nil
}

func (c *Option) skipScan() bool {
	if c.ClearCache || c.DownloadDBOnly || c.Reset {
		return true
	}
	return false
}
