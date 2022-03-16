package option

import (
	"net/http"
	"strings"

	"github.com/urfave/cli/v2"
)

type RemoteOption struct {
	RemoteAddr    string
	CustomHeaders http.Header
}

func NewRemoteOption(c *cli.Context) RemoteOption {
	r := RemoteOption{
		RemoteAddr: c.String("remote"),
	}
	r.CustomHeaders = splitCustomHeaders(c.StringSlice("custom-headers"))
	if token := c.String("token"); token != "" {
		r.CustomHeaders.Set(c.String("token-header"), token)
	}
	return r
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
