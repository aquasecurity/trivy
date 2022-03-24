package option

import (
	"net/http"
	"strings"

	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
)

const DefaultTokenHeader = "Trivy-Token"

// RemoteOption holds options for client/server
type RemoteOption struct {
	RemoteAddr    string
	customHeaders []string
	token         string
	tokenHeader   string
	remote        string // deprecated

	// this field is populated in Init()
	CustomHeaders http.Header
}

func NewRemoteOption(c *cli.Context) RemoteOption {
	r := RemoteOption{
		RemoteAddr:    c.String("server"),
		customHeaders: c.StringSlice("custom-headers"),
		token:         c.String("token"),
		tokenHeader:   c.String("token-header"),
		remote:        c.String("remote"), // deprecated
	}

	return r
}

// Init initialize the options for client/server mode
func (c *RemoteOption) Init(logger *zap.SugaredLogger) {
	// for testability
	defer func() {
		c.token = ""
		c.tokenHeader = ""
		c.remote = ""
		c.customHeaders = nil
	}()

	// for backward compatibility, should be removed in the future
	if c.remote != "" {
		c.RemoteAddr = c.remote
	}

	if c.RemoteAddr == "" {
		switch {
		case len(c.customHeaders) > 0:
			logger.Warn(`"--custom-header"" can be used only with "--server"`)
		case c.token != "":
			logger.Warn(`"--token" can be used only with "--server"`)
		case c.tokenHeader != "" && c.tokenHeader != DefaultTokenHeader:
			logger.Warn(`'--token-header' can be used only with "--server"`)
		}
		return
	}

	c.CustomHeaders = splitCustomHeaders(c.customHeaders)
	if c.token != "" {
		c.CustomHeaders.Set(c.tokenHeader, c.token)
	}
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
