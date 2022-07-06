package flag

import (
	"net/http"
	"strings"

	"github.com/samber/lo"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/aquasecurity/trivy/pkg/log"
)

const (
	DefaultTokenHeader = "Trivy-Token"

	ServerFlag            = "server"
	CustomHeadersFlag     = "custom-headers"
	ServerTokenFlag       = "token"
	ServerTokenHeaderFlag = "token-header"
	ServerListenFlag      = "listen"
)

// RemoteFlags composes common printer flag structs
// used for commands requiring reporting logic.
type RemoteFlags struct {
	// for client/server
	Token       *string
	TokenHeader *string

	// for client
	ServerAddr    *string
	CustomHeaders *[]string

	// for server
	Listen *string
}

type RemoteOptions struct {
	Token       string
	TokenHeader string

	ServerAddr    string
	Listen        string
	CustomHeaders http.Header
}

func NewClientFlags() *RemoteFlags {
	return &RemoteFlags{
		ServerAddr:    lo.ToPtr(""),
		CustomHeaders: lo.ToPtr([]string{}),
		Token:         lo.ToPtr(""),
		TokenHeader:   lo.ToPtr(DefaultTokenHeader),
	}
}

func NewServerDefaultFlags() *RemoteFlags {
	return &RemoteFlags{
		Token:       lo.ToPtr(""),
		TokenHeader: lo.ToPtr(""),
		Listen:      lo.ToPtr("localhost:4954"),
	}
}

func (f *RemoteFlags) AddFlags(cmd *cobra.Command) {
	if f.ServerAddr != nil {
		cmd.Flags().String(ServerFlag, *f.ServerAddr, "server address")
	}
	if f.CustomHeaders != nil {
		cmd.Flags().StringSlice(CustomHeadersFlag, *f.CustomHeaders, "custom headers in client/server mode")
	}
	if f.Token != nil {
		cmd.Flags().String(ServerTokenFlag, *f.Token, "for authentication in client/server mode")
	}
	if f.TokenHeader != nil {
		cmd.Flags().String(ServerTokenHeaderFlag, *f.Token, "specify a header name for token in client/server mode")
	}
	if f.Listen != nil {
		cmd.Flags().String(ServerListenFlag, *f.Listen, "listen address")
	}
}

func (f *RemoteFlags) ToOptions() RemoteOptions {
	serverAddr := viper.GetString(ServerFlag)
	customHeaders := splitCustomHeaders(viper.GetStringSlice(CustomHeadersFlag))
	listen := viper.GetString(ServerListenFlag)
	token := viper.GetString(ServerTokenFlag)
	tokenHeader := viper.GetString(ServerTokenHeaderFlag)
	if tokenHeader == "" {
		tokenHeader = DefaultTokenHeader
	}

	if serverAddr == "" {
		switch {
		case len(lo.FromPtr(f.CustomHeaders)) > 0:
			log.Logger.Warn(`"--custom-header"" can be used only with "--server"`)
		case token != "" && listen == "":
			log.Logger.Warn(`"--token" can be used only with "--server"`)
		case tokenHeader != "" && tokenHeader != DefaultTokenHeader:
			log.Logger.Warn(`'--token-header' can be used only with "--server"`)
		}
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
