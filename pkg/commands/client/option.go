package client

import (
	"net/http"
	"strings"

	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/commands/option"
)

// Option holds the Trivy client options
type Option struct {
	option.GlobalOption
	option.ArtifactOption
	option.ImageOption
	option.ReportOption
	option.ConfigOption

	ListAllPkgs   bool
	RemoteAddr    string
	token         string
	tokenHeader   string
	customHeaders []string
	// this field is populated in Init()
	CustomHeaders http.Header
}

// NewOption is the factory method for Option
func NewOption(c *cli.Context) (Option, error) {
	gc, err := option.NewGlobalOption(c)
	if err != nil {
		return Option{}, xerrors.Errorf("failed to initialize global options: %w", err)
	}

	return Option{
		GlobalOption:   gc,
		ArtifactOption: option.NewArtifactOption(c),
		ImageOption:    option.NewImageOption(c),
		ReportOption:   option.NewReportOption(c),
		ConfigOption:   option.NewConfigOption(c),
		ListAllPkgs:    c.Bool("list-all-pkgs"),
		RemoteAddr:     c.String("remote"),
		token:          c.String("token"),
		tokenHeader:    c.String("token-header"),
		customHeaders:  c.StringSlice("custom-headers"),
	}, nil
}

// Init initializes the options
func (c *Option) Init() (err error) {
	// --clear-cache doesn't conduct the scan
	if c.ClearCache {
		return nil
	}

	c.CustomHeaders = splitCustomHeaders(c.customHeaders)

	// add token to custom headers
	if c.token != "" {
		c.CustomHeaders.Set(c.tokenHeader, c.token)
	}

	if err := c.ReportOption.Init(c.Logger); err != nil {
		return err
	}

	if err := c.ArtifactOption.Init(c.Context, c.Logger); err != nil {
		return err
	}

	return nil
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
