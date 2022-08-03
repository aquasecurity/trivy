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
	ServerTokenFlag = Flag{
		Name:       "token",
		ConfigName: "server.token",
		Value:      "",
		Usage:      "for authentication in client/server mode",
	}
	ServerTokenHeaderFlag = Flag{
		Name:       "token-header",
		ConfigName: "server.token-header",
		Value:      DefaultTokenHeader,
		Usage:      "specify a header name for token in client/server mode",
	}
	ServerAddrFlag = Flag{
		Name:       "server",
		ConfigName: "server.addr",
		Value:      "",
		Usage:      "server address in client mode",
	}
	ServerCustomHeadersFlag = Flag{
		Name:       "custom-headers",
		ConfigName: "server.custom-headers",
		Value:      []string{},
		Usage:      "custom headers in client mode",
	}
	ServerListenFlag = Flag{
		Name:       "listen",
		ConfigName: "server.listen",
		Value:      "localhost:4954",
		Usage:      "listen address in server mode",
	}
)

// RemoteFlagGroup composes common printer flag structs
// used for commands requiring reporting logic.
type RemoteFlagGroup struct {
	// for client/server
	Token       *Flag
	TokenHeader *Flag

	// for client
	ServerAddr    *Flag
	CustomHeaders *Flag

	// for server
	Listen *Flag
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
		Token:         &ServerTokenFlag,
		TokenHeader:   &ServerTokenHeaderFlag,
		ServerAddr:    &ServerAddrFlag,
		CustomHeaders: &ServerCustomHeadersFlag,
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

func (f *RemoteFlagGroup) Flags() []*Flag {
	return []*Flag{f.Token, f.TokenHeader, f.ServerAddr, f.CustomHeaders, f.Listen}
}

func (f *RemoteFlagGroup) ToOptions() RemoteOptions {
	serverAddr := getString(f.ServerAddr)
	customHeaders := splitCustomHeaders(getStringSlice(f.CustomHeaders))
	listen := getString(f.Listen)
	token := getString(f.Token)
	tokenHeader := getString(f.TokenHeader)

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
