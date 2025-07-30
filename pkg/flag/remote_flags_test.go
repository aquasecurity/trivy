package flag_test

import (
	"net/http"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
)

func TestRemoteFlagGroup_ToOptions(t *testing.T) {
	type fields struct {
		Server        string
		CustomHeaders []string
		Token         string
		TokenHeader   string
	}
	tests := []struct {
		name     string
		fields   fields
		want     flag.RemoteOptions
		wantLogs []string
		wantErr  string
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
		{
			name: "server address without schema",
			fields: fields{
				Server: "localhost:8080",
			},
			wantErr: "server address must use HTTP or HTTPS schema, got 'localhost'",
		},
		{
			name: "server address with invalid schema",
			fields: fields{
				Server: "ftp://localhost:8080",
			},
			wantErr: "server address must use HTTP or HTTPS schema, got 'ftp'",
		},
		{
			name: "server address with malformed URL",
			fields: fields{
				Server: "http://[::1:8080",
			},
			wantErr: "invalid server address format",
		},
		{
			name: "server address with https schema",
			fields: fields{
				Server:      "https://localhost:4954",
				TokenHeader: "Trivy-Token",
			},
			want: flag.RemoteOptions{
				CustomHeaders: http.Header{},
				ServerAddr:    "https://localhost:4954",
				TokenHeader:   "Trivy-Token",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := newLogger(log.LevelWarn)

			viper.Set(flag.ServerAddrFlag.ConfigName, tt.fields.Server)
			viper.Set(flag.ServerCustomHeadersFlag.ConfigName, tt.fields.CustomHeaders)
			viper.Set(flag.ServerTokenFlag.ConfigName, tt.fields.Token)
			viper.Set(flag.ServerTokenHeaderFlag.ConfigName, tt.fields.TokenHeader)

			// Assert options
			f := &flag.RemoteFlagGroup{
				ServerAddr:    flag.ServerAddrFlag.Clone(),
				CustomHeaders: flag.ServerCustomHeadersFlag.Clone(),
				Token:         flag.ServerTokenFlag.Clone(),
				TokenHeader:   flag.ServerTokenHeaderFlag.Clone(),
			}
			flags := flag.Flags{f}
			got, err := flags.ToOptions(nil)

			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got.RemoteOptions)

			// Assert log messages
			assert.Equal(t, tt.wantLogs, out.Messages(), tt.name)
		})
	}
}
