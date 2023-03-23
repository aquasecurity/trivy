package flag_test

import (
	"net/http"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
)

func TestRemoteFlagGroup_ToOptions(t *testing.T) {
	type fields struct {
		Server        string
		CustomHeaders []string
		Token         string
		TokenHeader   string
		PathPrefix    string
	}
	tests := []struct {
		name     string
		fields   fields
		want     flag.RemoteOptions
		wantLogs []string
	}{
		{
			name: "happy",
			fields: fields{
				Server: "http://localhost:4954",
				CustomHeaders: []string{
					"x-api-token:foo bar",
					"Authorization:user:password",
				},
				Token:       "token",
				TokenHeader: "Trivy-Token",
			},
			want: flag.RemoteOptions{
				ServerAddr: "http://localhost:4954",
				CustomHeaders: http.Header{
					"X-Api-Token":   []string{"foo bar"},
					"Authorization": []string{"user:password"},
					"Trivy-Token":   []string{"token"},
				},
				Token:       "token",
				TokenHeader: "Trivy-Token",
			},
		},
		{
			name: "happy with path prefix",
			fields: fields{
				Server: "http://localhost:4954",
				CustomHeaders: []string{
					"x-api-token:foo bar",
					"Authorization:user:password",
				},
				Token:       "token",
				TokenHeader: "Trivy-Token",
				PathPrefix:  "/custom-path-prefix",
			},
			want: flag.RemoteOptions{
				ServerAddr: "http://localhost:4954",
				CustomHeaders: http.Header{
					"X-Api-Token":   []string{"foo bar"},
					"Authorization": []string{"user:password"},
					"Trivy-Token":   []string{"token"},
				},
				Token:       "token",
				TokenHeader: "Trivy-Token",
				PathPrefix:  "/custom-path-prefix",
			},
		},
		{
			name: "path prefix and no server",
			fields: fields{
				TokenHeader: "Trivy-Token",
				PathPrefix:  "/custom-path-prefix",
			},
			want: flag.RemoteOptions{
				CustomHeaders: http.Header{},
				TokenHeader:   "Trivy-Token",
				PathPrefix:    "/custom-path-prefix",
			},
			wantLogs: []string{
				`"--path-prefix" can be used only with "--server"`,
			},
		},
		{
			name: "custom headers and no server",
			fields: fields{
				CustomHeaders: []string{
					"Authorization:user:password",
				},
				TokenHeader: "Trivy-Token",
			},
			want: flag.RemoteOptions{
				CustomHeaders: http.Header{
					"Authorization": []string{"user:password"},
				},
				TokenHeader: "Trivy-Token",
			},
			wantLogs: []string{
				`"--custom-header" can be used only with "--server"`,
			},
		},
		{
			name: "token and no server",
			fields: fields{
				Token: "token",
			},
			want: flag.RemoteOptions{
				CustomHeaders: http.Header{},
				Token:         "token",
			},
			wantLogs: []string{
				`"--token" can be used only with "--server"`,
			},
		},
		{
			name: "token header and no token",
			fields: fields{
				Server:      "http://localhost:4954",
				TokenHeader: "Non-Default",
			},
			want: flag.RemoteOptions{
				CustomHeaders: http.Header{},
				ServerAddr:    "http://localhost:4954",
				TokenHeader:   "Non-Default",
			},
			wantLogs: []string{
				`"--token-header" should be used with "--token"`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			level := zap.WarnLevel
			core, obs := observer.New(level)
			log.Logger = zap.New(core).Sugar()

			viper.Set(flag.ServerAddrFlag.ConfigName, tt.fields.Server)
			viper.Set(flag.ServerCustomHeadersFlag.ConfigName, tt.fields.CustomHeaders)
			viper.Set(flag.ServerTokenFlag.ConfigName, tt.fields.Token)
			viper.Set(flag.ServerTokenHeaderFlag.ConfigName, tt.fields.TokenHeader)
			viper.Set(flag.ServerPathPrefixFlag.ConfigName, tt.fields.PathPrefix)

			// Assert options
			f := &flag.RemoteFlagGroup{
				ServerAddr:    &flag.ServerAddrFlag,
				CustomHeaders: &flag.ServerCustomHeadersFlag,
				Token:         &flag.ServerTokenFlag,
				TokenHeader:   &flag.ServerTokenHeaderFlag,
				PathPrefix:    &flag.ServerPathPrefixFlag,
			}
			got := f.ToOptions()
			assert.Equalf(t, tt.want, got, "ToOptions()")

			// Assert log messages
			var gotMessages []string
			for _, entry := range obs.AllUntimed() {
				gotMessages = append(gotMessages, entry.Message)
			}
			assert.Equal(t, tt.wantLogs, gotMessages, tt.name)
		})
	}
}
