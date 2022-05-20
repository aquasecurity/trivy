package option

import (
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/log"
)

// Allow for building trivy with networking capabilities completely disabled
var disableNetworking string

// GlobalOption holds the global options for trivy
type GlobalOption struct {
	Context *cli.Context
	Logger  *zap.SugaredLogger

	AppVersion        string
	Quiet             bool
	Debug             bool
	CacheDir          string
	DisableNetworking bool
}

// NewGlobalOption is the factory method to return GlobalOption
func NewGlobalOption(c *cli.Context) (GlobalOption, error) {
	quiet := c.Bool("quiet")
	debug := c.Bool("debug")
	noNetworking := disableNetworking == "true"
	logger, err := log.NewLogger(debug, quiet)
	if err != nil {
		return GlobalOption{}, xerrors.New("failed to create a logger")
	}

	return GlobalOption{
		Context: c,
		Logger:  logger,

		AppVersion:        c.App.Version,
		Quiet:             quiet,
		Debug:             debug,
		CacheDir:          c.String("cache-dir"),
		DisableNetworking: noNetworking,
	}, nil
}
