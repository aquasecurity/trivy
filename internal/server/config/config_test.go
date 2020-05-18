package config

import (
	"flag"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v2"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want Config
	}{
		{
			name: "happy path",
			args: []string{"-quiet", "--no-progress", "--reset", "--skip-update"},
			want: Config{
				Quiet:      true,
				Reset:      true,
				SkipUpdate: true,
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
			set.Bool("skip-update", false, "")

			c := cli.NewContext(app, set, nil)
			_ = set.Parse(tt.args)

			tt.want.context = c

			got := New(c)
			assert.Equal(t, tt.want, got, tt.name)
		})
	}
}

func TestConfig_Init(t *testing.T) {
	type fields struct {
		context        *cli.Context
		Quiet          bool
		Debug          bool
		CacheDir       string
		Reset          bool
		DownloadDBOnly bool
		SkipUpdate     bool
		ClearCache     bool
		Input          string
		output         string
		Format         string
		Template       string
		Timeout        time.Duration
		vulnType       string
		Light          bool
		severities     string
		IgnoreFile     string
		IgnoreUnfixed  bool
		ExitCode       int
		ImageName      string
		VulnType       []string
		Output         *os.File
		Severities     []dbTypes.Severity
		AppVersion     string
		onlyUpdate     string
		refresh        bool
		autoRefresh    bool
	}
	tests := []struct {
		name    string
		fields  fields
		args    []string
		logs    []string
		want    Config
		wantErr string
	}{
		{
			name: "happy path",
			fields: fields{
				severities: "CRITICAL",
				vulnType:   "os",
				Quiet:      true,
			},
			args: []string{"alpine:3.10"},
			want: Config{
				Quiet: true,
			},
		},
		{
			name: "happy path: reset",
			fields: fields{
				severities: "CRITICAL",
				vulnType:   "os",
				Reset:      true,
			},
			args: []string{"alpine:3.10"},
			want: Config{
				Reset: true,
			},
		},
		{
			name: "sad: skip and download db",
			fields: fields{
				refresh:        true,
				SkipUpdate:     true,
				DownloadDBOnly: true,
			},
			args:    []string{"alpine:3.10"},
			wantErr: "The --skip-update and --download-db-only option can not be specified both",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := cli.NewApp()
			set := flag.NewFlagSet("test", 0)
			ctx := cli.NewContext(app, set, nil)
			_ = set.Parse(tt.args)

			c := &Config{
				context:        ctx,
				Quiet:          tt.fields.Quiet,
				Debug:          tt.fields.Debug,
				CacheDir:       tt.fields.CacheDir,
				Reset:          tt.fields.Reset,
				DownloadDBOnly: tt.fields.DownloadDBOnly,
				SkipUpdate:     tt.fields.SkipUpdate,
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

			tt.want.context = ctx
			assert.Equal(t, &tt.want, c, tt.name)
		})
	}
}
