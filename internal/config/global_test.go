package config_test

import (
	"flag"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v2"

	"github.com/aquasecurity/trivy/internal/config"
)

func TestNewGlobalConfig(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want config.GlobalConfig
	}{
		{
			name: "happy path",
			args: []string{"--quiet", "--debug"},
			want: config.GlobalConfig{
				Quiet: true,
				Debug: true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := &cli.App{}
			set := flag.NewFlagSet("test", 0)
			set.Bool("debug", false, "")
			set.Bool("quiet", false, "")

			c := cli.NewContext(app, set, nil)
			_ = set.Parse(tt.args)

			got, err := config.NewGlobalConfig(c)
			require.NoError(t, err, err)
			assert.Equal(t, tt.want.Quiet, got.Quiet, tt.name)
			assert.Equal(t, tt.want.Debug, got.Debug, tt.name)
			assert.Equal(t, tt.want.CacheDir, got.CacheDir, tt.name)
		})
	}
}
