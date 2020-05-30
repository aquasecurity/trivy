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

func TestNewImageConfig(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want config.ImageConfig
	}{
		{
			name: "happy path",
			args: []string{"--clear-cache", "--input", "/tmp/alpine.tar"},
			want: config.ImageConfig{
				Input:      "/tmp/alpine.tar",
				ClearCache: true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := &cli.App{}
			set := flag.NewFlagSet("test", 0)
			set.Bool("clear-cache", false, "")
			set.String("input", "", "")

			c := cli.NewContext(app, set, nil)
			_ = set.Parse(tt.args)

			got := config.NewImageConfig(c)
			assert.Equal(t, tt.want, got, tt.name)
		})
	}
}

func TestImageConfig_Init(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		logs    []string
		want    config.ImageConfig
		wantErr string
	}{
		{
			name: "happy path",
			args: []string{"alpine:3.10"},
			want: config.ImageConfig{
				ImageName: "alpine:3.10",
			},
		},
		{
			name: "with latest tag",
			args: []string{"gcr.io/distroless/base"},
			logs: []string{
				"You should avoid using the :latest tag as it is cached. You need to specify '--clear-cache' option when :latest image is changed",
			},
			want: config.ImageConfig{
				ImageName: "gcr.io/distroless/base",
			},
		},
		{
			name: "sad: multiple image names",
			args: []string{"centos:7", "alpine:3.10"},
			logs: []string{
				"multiple images cannot be specified",
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

			c := &config.ImageConfig{}

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

			assert.Equal(t, &tt.want, c, tt.name)
		})
	}
}
