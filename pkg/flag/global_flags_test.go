package flag_test

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
)

func TestGlobalFlagGroup_LogFormat(t *testing.T) {
	tests := []struct {
		name    string
		cliArgs []string
		envs    map[string]string
		want    log.Format
		wantErr string
	}{
		{
			name: "default",
			want: log.FormatText,
		},
		{
			name:    "text",
			cliArgs: []string{"--log-format", "text"},
			want:    log.FormatText,
		},
		{
			name:    "json",
			cliArgs: []string{"--log-format", "json"},
			want:    log.FormatJSON,
		},
		{
			name: "environment variable",
			envs: map[string]string{
				"TRIVY_LOG_FORMAT": "json",
			},
			want: log.FormatJSON,
		},
		{
			name:    "unknown format",
			cliArgs: []string{"--log-format", "yaml"},
			wantErr: `invalid argument "yaml" for "--log-format" flag`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(viper.Reset)

			for k, v := range tt.envs {
				t.Setenv(k, v)
			}

			cmd := &cobra.Command{
				Use: "test",
				Run: func(_ *cobra.Command, _ []string) {},
			}

			// Global flags are registered on the root command, not through Flags.AddFlags.
			globalFlags := flag.NewGlobalFlagGroup()
			globalFlags.AddFlags(cmd)
			require.NoError(t, cmd.ParseFlags(tt.cliArgs))
			require.NoError(t, globalFlags.Bind(cmd))

			flags := flag.Flags{globalFlags}
			got, err := flags.ToOptions(nil)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)

			assert.Equal(t, tt.want, got.LogFormat)
		})
	}
}
