package config_test

import (
	"flag"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/aquasecurity/trivy/internal/config"
)

func TestImageConfig_Init(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		logs    []string
		wantErr string
	}{
		{
			name: "happy path",
			args: []string{"alpine:3.10"},
		},
		{
			name: "with latest tag",
			args: []string{"gcr.io/distroless/base"},
			logs: []string{
				"You should avoid using the :latest tag as it is cached. You need to specify '--clear-cache' option when :latest image is changed",
			},
		},
		{
			name:    "sad: invalid image name",
			args:    []string{`!"#$%&'()`},
			wantErr: "could not parse reference",
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

			c := config.NewImageConfig(ctx)

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
		})
	}
}
