package config_test

import (
	"flag"
	"testing"

	"github.com/aquasecurity/trivy/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestArtifactConfig_Init(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		logs    []string
		want    config.ArtifactConfig
		wantErr string
	}{
		{
			name: "happy path",
			args: []string{"alpine:3.10"},
			want: config.ArtifactConfig{
				Target: "alpine:3.10",
			},
		},
		{
			name: "sad: multiple image names",
			args: []string{"centos:7", "alpine:3.10"},
			logs: []string{
				"multiple targets cannot be specified",
			},
			wantErr: "arguments error",
		},
		{
			name: "sad: no image name",
			logs: []string{
				"trivy requires at least 1 argument or --input option",
			},
			wantErr: "arguments error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			core, obs := observer.New(zap.InfoLevel)
			logger := zap.New(core)

			app := cli.NewApp()
			set := flag.NewFlagSet("test", 0)
			ctx := cli.NewContext(app, set, nil)
			_ = set.Parse(tt.args)

			c := config.NewArtifactConfig(ctx)

			err := c.Init(ctx.Args(), logger.Sugar())

			// tests log messages
			var gotMessages []string
			for _, entry := range obs.AllUntimed() {
				gotMessages = append(gotMessages, entry.Message)
			}
			assert.Equal(t, tt.logs, gotMessages, tt.name)

			// test the error
			switch {
			case tt.wantErr != "":
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
				return
			default:
				assert.NoError(t, err, tt.name)
			}

			assert.Equal(t, tt.want, c, tt.name)
		})
	}
}
