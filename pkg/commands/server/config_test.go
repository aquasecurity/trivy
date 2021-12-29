package server_test

import (
	"flag"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v2"

	"github.com/aquasecurity/trivy/pkg/commands/option"
	"github.com/aquasecurity/trivy/pkg/commands/server"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want server.Config
	}{
		{
			name: "happy path",
			args: []string{"-quiet", "--no-progress", "--reset", "--skip-db-update", "--listen", "localhost:8080"},
			want: server.Config{
				GlobalOption: option.GlobalOption{
					Quiet: true,
				},
				DBOption: option.DBOption{
					Reset:        true,
					SkipDBUpdate: true,
					NoProgress:   true,
				},
				Listen: "localhost:8080",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := &cli.App{}
			set := flag.NewFlagSet("test", 0)
			set.Bool("quiet", false, "")
			set.Bool("no-progress", false, "")
			set.Bool("reset", false, "")
			set.Bool("skip-db-update", false, "")
			set.String("listen", "", "")

			ctx := cli.NewContext(app, set, nil)
			_ = set.Parse(tt.args)

			tt.want.GlobalOption.Context = ctx

			got := server.NewConfig(ctx)
			assert.Equal(t, tt.want.GlobalOption.Quiet, got.Quiet, tt.name)
			assert.Equal(t, tt.want.DBOption, got.DBOption, tt.name)
			assert.Equal(t, tt.want.Listen, got.Listen, tt.name)
		})
	}
}

func TestConfig_Init(t *testing.T) {
	tests := []struct {
		name         string
		globalConfig option.GlobalOption
		dbConfig     option.DBOption
		args         []string
		wantErr      string
	}{
		{
			name: "happy path",
			args: []string{"alpine:3.10"},
		},
		{
			name: "happy path: reset",
			dbConfig: option.DBOption{
				Reset: true,
			},
			args: []string{"alpine:3.10"},
		},
		{
			name: "sad: skip and download db",
			dbConfig: option.DBOption{
				SkipDBUpdate:   true,
				DownloadDBOnly: true,
			},
			args:    []string{"alpine:3.10"},
			wantErr: "--skip-db-update and --download-db-only options can not be specified both",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &server.Config{
				DBOption: tt.dbConfig,
			}

			err := c.Init()

			// test the error
			switch {
			case tt.wantErr != "":
				require.NotNil(t, err, tt.name)
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
				return
			default:
				assert.NoError(t, err, tt.name)
			}
		})
	}
}
