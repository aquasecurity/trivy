package artifact

import (
	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"
	"net/http"
	"strings"

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

	// For policy downloading
	NoProgress bool

	// We don't want to allow disabled analyzers to be passed by users,
	// but it differs depending on scanning modes.
	DisabledAnalyzers []analyzer.Type

	RemoteAddr    string
	token         string
	tokenHeader   string
	customHeaders []string
	// this field is populated in Init()
	CustomHeaders http.Header
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
		NoProgress:     c.Bool("no-progress"),
		RemoteAddr:     c.String("remote"),
		token:          c.String("token"),
		tokenHeader:    c.String("token-header"),
		customHeaders:  c.StringSlice("custom-headers"),
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

	c.CustomHeaders = splitCustomHeaders(c.customHeaders)
	// add token to custom headers
	if c.token != "" {
		c.CustomHeaders.Set(c.tokenHeader, c.token)
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
	return nil
}

func (c *Option) skipScan() bool {
	if c.ClearCache || c.DownloadDBOnly || c.Reset {
		return true
	}
	return false
}

func splitCustomHeaders(headers []string) http.Header {
	result := make(http.Header)
	for _, header := range headers {
		// e.g. x-api-token:XXX
		s := strings.SplitN(header, ":", 2)
		if len(s) != 2 {
			continue
		}
		result.Set(s[0], s[1])
	}
	return result
}
