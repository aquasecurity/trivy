package flag

import (
	"net/http"
	"strings"

	"github.com/aquasecurity/trivy/pkg/log"
)

const (
	DefaultTokenHeader = "Trivy-Token"
)

var (
	ServerTokenFlag = Flag[string]{
		Name:       "token",
		ConfigName: "server.token",
		Usage:      "for authentication in client/server mode",
	}
	ServerTokenHeaderFlag = Flag[string]{
		Name:       "token-header",
		ConfigName: "server.token-header",
		Default:    DefaultTokenHeader,
		Usage:      "specify a header name for token in client/server mode",
	}
	ServerAddrFlag = Flag[string]{
		Name:       "server",
		ConfigName: "server.addr",
		Usage:      "server address in client mode",
	}
	ServerCustomHeadersFlag = Flag[[]string]{
		Name:       "custom-headers",
		ConfigName: "server.custom-headers",
		Usage:      "custom headers in client mode",
	}
	ServerListenFlag = Flag[string]{
		Name:       "listen",
		ConfigName: "server.listen",
		Default:    "localhost:4954",
		Usage:      "listen address in server mode",
	}
)

// RemoteFlagGroup composes common printer flag structs
// used for commands requiring reporting logic.
type RemoteFlagGroup struct {
	// for client/server
	Token       *Flag[string]
	TokenHeader *Flag[string]

	// for client
	ServerAddr    *Flag[string]
	CustomHeaders *Flag[[]string]

	// for server
	Listen *Flag[string]
}

type RemoteOptions struct {
	Token       string
	TokenHeader string

	ServerAddr    string
	Listen        string
	CustomHeaders http.Header
}

func NewClientFlags() *RemoteFlagGroup {
	return &RemoteFlagGroup{
		Token:         ServerTokenFlag.Clone(),
		TokenHeader:   ServerTokenHeaderFlag.Clone(),
		ServerAddr:    ServerAddrFlag.Clone(),
		CustomHeaders: ServerCustomHeadersFlag.Clone(),
	}
}

func NewServerFlags() *RemoteFlagGroup {
	return &RemoteFlagGroup{
		Token:       &ServerTokenFlag,
		TokenHeader: &ServerTokenHeaderFlag,
		Listen:      &ServerListenFlag,
	}
}

func (f *RemoteFlagGroup) Name() string {
	return "Client/Server"
}

func (f *RemoteFlagGroup) Flags() []Flagger {
	return []Flagger{
		f.Token,
		f.TokenHeader,
		f.ServerAddr,
		f.CustomHeaders,
		f.Listen,
	}
}

func (f *RemoteFlagGroup) ToOptions() (RemoteOptions, error) {
	if err := parseFlags(f); err != nil {
		return RemoteOptions{}, err
	}

	serverAddr := f.ServerAddr.Value()
	customHeaders := splitCustomHeaders(f.CustomHeaders.Value())
	listen := f.Listen.Value()
	token := f.Token.Value()
	tokenHeader := f.TokenHeader.Value()

	if serverAddr == "" && listen == "" {
		switch {
		case len(customHeaders) > 0:
			log.Logger.Warn(`"--custom-header" can be used only with "--server"`)
		case token != "":
			log.Logger.Warn(`"--token" can be used only with "--server"`)
		case tokenHeader != "" && tokenHeader != DefaultTokenHeader:
			log.Logger.Warn(`"--token-header" can be used only with "--server"`)
		}
	}

	if token == "" && tokenHeader != DefaultTokenHeader {
		log.Logger.Warn(`"--token-header" should be used with "--token"`)
	}

	if token != "" && tokenHeader != "" {
		customHeaders.Set(tokenHeader, token)
	}

	return RemoteOptions{
		Token:         token,
		TokenHeader:   tokenHeader,
		ServerAddr:    serverAddr,
		CustomHeaders: customHeaders,
		Listen:        listen,
	}, nil
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
