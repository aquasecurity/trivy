package config

import (
	"flag"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

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
				NoProgress: true,
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

			_, err := New(c)
			assert.NoError(t, err, tt.name)
		})
	}
}

func TestConfig_Init(t *testing.T) {
	type fields struct {
		context        *cli.Context
		Quiet          bool
		NoProgress     bool
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
				Severities: []dbTypes.Severity{dbTypes.SeverityCritical},
				severities: "CRITICAL",
				ImageName:  "alpine:3.10",
				VulnType:   []string{"os"},
				vulnType:   "os",
				Output:     os.Stdout,
				Quiet:      true,
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
				Severities: []dbTypes.Severity{dbTypes.SeverityCritical},
				severities: "CRITICAL",
				VulnType:   []string{"os"},
				vulnType:   "os",
				Reset:      true,
			},
		},
		{
			name: "happy path with an unknown severity",
			fields: fields{
				severities: "CRITICAL,INVALID",
				vulnType:   "os,library",
			},
			args: []string{"centos:7"},
			logs: []string{
				"unknown severity option: unknown severity: INVALID",
			},
			want: Config{
				Severities: []dbTypes.Severity{dbTypes.SeverityCritical, dbTypes.SeverityUnknown},
				severities: "CRITICAL,INVALID",
				ImageName:  "centos:7",
				VulnType:   []string{"os", "library"},
				vulnType:   "os,library",
				Output:     os.Stdout,
			},
		},
		{
			name: "deprecated options",
			fields: fields{
				onlyUpdate: "alpine",
				severities: "LOW",
				vulnType:   "os,library",
			},
			args: []string{"debian:buster"},
			logs: []string{
				"--only-update, --refresh and --auto-refresh are unnecessary and ignored now. These commands will be removed in the next version.",
			},
			want: Config{
				Severities: []dbTypes.Severity{dbTypes.SeverityLow},
				severities: "LOW",
				ImageName:  "debian:buster",
				VulnType:   []string{"os", "library"},
				vulnType:   "os,library",
				Output:     os.Stdout,
				onlyUpdate: "alpine",
			},
		},
		{
			name: "invalid option combination: --template enabled without --format",
			fields: fields{
				Template:   "@contrib/gitlab.tpl",
				severities: "LOW",
			},
			args: []string{"gitlab/gitlab-ce:12.7.2-ce.0"},
			logs: []string{
				"--template is ignored because --format template is not specified. Use --template option with --format template option.",
			},
			want: Config{
				ImageName:  "gitlab/gitlab-ce:12.7.2-ce.0",
				Output:     os.Stdout,
				Severities: []dbTypes.Severity{dbTypes.SeverityLow},
				severities: "LOW",
				Template:   "@contrib/gitlab.tpl",
				VulnType:   []string{""},
			},
		},
		{
			name: "invalid option combination: --template and --format json",
			fields: fields{
				Format:     "json",
				Template:   "@contrib/gitlab.tpl",
				severities: "LOW",
			},
			args: []string{"gitlab/gitlab-ce:12.7.2-ce.0"},
			logs: []string{
				"--template is ignored because --format json is specified. Use --template option with --format template option.",
			},
			want: Config{
				Format:     "json",
				ImageName:  "gitlab/gitlab-ce:12.7.2-ce.0",
				Output:     os.Stdout,
				Severities: []dbTypes.Severity{dbTypes.SeverityLow},
				severities: "LOW",
				Template:   "@contrib/gitlab.tpl",
				VulnType:   []string{""},
			},
		},
		{
			name: "invalid option combination: --format template without --template",
			fields: fields{
				Format:     "template",
				severities: "LOW",
			},
			args: []string{"gitlab/gitlab-ce:12.7.2-ce.0"},
			logs: []string{
				"--format template is ignored because --template not is specified. Specify --template option when you use --format template.",
			},
			want: Config{
				Format:     "template",
				ImageName:  "gitlab/gitlab-ce:12.7.2-ce.0",
				Output:     os.Stdout,
				Severities: []dbTypes.Severity{dbTypes.SeverityLow},
				severities: "LOW",
				VulnType:   []string{""},
			},
		},
		{
			name: "with latest tag",
			fields: fields{
				onlyUpdate: "alpine",
				severities: "LOW",
				vulnType:   "os,library",
			},
			args: []string{"gcr.io/distroless/base"},
			logs: []string{
				"--only-update, --refresh and --auto-refresh are unnecessary and ignored now. These commands will be removed in the next version.",
				"You should avoid using the :latest tag as it is cached. You need to specify '--clear-cache' option when :latest image is changed",
			},
			want: Config{
				Severities: []dbTypes.Severity{dbTypes.SeverityLow},
				severities: "LOW",
				ImageName:  "gcr.io/distroless/base",
				VulnType:   []string{"os", "library"},
				vulnType:   "os,library",
				Output:     os.Stdout,
				onlyUpdate: "alpine",
			},
		},
		{
			name: "sad: skip and download db",
			fields: fields{
				refresh:        true,
				SkipUpdate:     true,
				DownloadDBOnly: true,
			},
			args: []string{"alpine:3.10"},
			logs: []string{
				"--only-update, --refresh and --auto-refresh are unnecessary and ignored now. These commands will be removed in the next version.",
			},
			wantErr: "The --skip-update and --download-db-only option can not be specified both",
		},
		{
			name: "sad: multiple image names",
			fields: fields{
				severities: "MEDIUM",
			},
			args: []string{"centos:7", "alpine:3.10"},
			logs: []string{
				"multiple images cannot be specified",
			},
			wantErr: "arguments error",
		},
		{
			name: "sad: no image name",
			fields: fields{
				severities: "MEDIUM",
			},
			logs: []string{
				"trivy requires at least 1 argument or --input option",
			},
			wantErr: "arguments error",
		},
		{
			name: "sad: invalid image name",
			fields: fields{
				severities: "HIGH",
			},
			args:    []string{`!"#$%&'()`},
			wantErr: "invalid image: parsing image",
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

			c := &Config{
				context:        ctx,
				logger:         logger.Sugar(),
				Quiet:          tt.fields.Quiet,
				NoProgress:     tt.fields.NoProgress,
				Debug:          tt.fields.Debug,
				CacheDir:       tt.fields.CacheDir,
				Reset:          tt.fields.Reset,
				DownloadDBOnly: tt.fields.DownloadDBOnly,
				SkipUpdate:     tt.fields.SkipUpdate,
				ClearCache:     tt.fields.ClearCache,
				Input:          tt.fields.Input,
				output:         tt.fields.output,
				Format:         tt.fields.Format,
				Template:       tt.fields.Template,
				Timeout:        tt.fields.Timeout,
				vulnType:       tt.fields.vulnType,
				Light:          tt.fields.Light,
				severities:     tt.fields.severities,
				IgnoreFile:     tt.fields.IgnoreFile,
				IgnoreUnfixed:  tt.fields.IgnoreUnfixed,
				ExitCode:       tt.fields.ExitCode,
				ImageName:      tt.fields.ImageName,
				Output:         tt.fields.Output,
				onlyUpdate:     tt.fields.onlyUpdate,
				refresh:        tt.fields.refresh,
				autoRefresh:    tt.fields.autoRefresh,
			}

			err := c.Init()

			// tests log messages
			var gotMessages []string
			for _, entry := range obs.AllUntimed() {
				gotMessages = append(gotMessages, entry.Message)
			}
			assert.Equal(t, tt.logs, gotMessages, tt.name)

			// test the error
			switch {
			case tt.wantErr != "":
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
				return
			default:
				assert.NoError(t, err, tt.name)
			}

			tt.want.context = ctx
			tt.want.logger = logger.Sugar()
			assert.Equal(t, &tt.want, c, tt.name)
		})
	}
}
