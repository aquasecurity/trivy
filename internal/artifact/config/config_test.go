package config

import (
	"flag"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/internal/config"
)

func TestConfig_Init(t *testing.T) {
	tests := []struct {
		name         string
		globalConfig config.GlobalConfig
		dbConfig     config.DBConfig
		imageConfig  config.ImageConfig
		reportConfig config.ReportConfig
		args         []string
		logs         []string
		want         Config
		wantErr      string
	}{
		{
			name: "happy path",
			reportConfig: config.ReportConfig{
				Severities: []dbTypes.Severity{dbTypes.SeverityCritical},
				VulnType:   []string{"os"},
			},
			args: []string{"--severity", "CRITICAL", "--vuln-type", "os", "--quiet", "alpine:3.10"},
			want: Config{
				GlobalConfig: config.GlobalConfig{
					Quiet: true,
				},
				ArtifactConfig: config.ArtifactConfig{
					Target: "alpine:3.10",
				},
				ReportConfig: config.ReportConfig{
					Severities: []dbTypes.Severity{dbTypes.SeverityCritical},
					VulnType:   []string{"os"},
					Output:     os.Stdout,
				},
			},
		},
		{
			name: "happy path: reset",
			args: []string{"--reset"},
			want: Config{
				DBConfig: config.DBConfig{
					Reset: true,
				},
				ReportConfig: config.ReportConfig{
					Severities: []dbTypes.Severity{dbTypes.SeverityCritical},
					Output:     os.Stdout,
					VulnType:   []string{"os", "library"},
				},
			},
		},
		{
			name: "happy path with an unknown severity",
			args: []string{"--severity", "CRITICAL,INVALID", "centos:7"},
			logs: []string{
				"unknown severity option: unknown severity: INVALID",
			},
			want: Config{
				ReportConfig: config.ReportConfig{
					Severities: []dbTypes.Severity{dbTypes.SeverityCritical, dbTypes.SeverityUnknown},
					Output:     os.Stdout,
					VulnType:   []string{"os", "library"},
				},
				ArtifactConfig: config.ArtifactConfig{
					Target: "centos:7",
				},
			},
		},
		{
			name: "deprecated options",
			args: []string{"--only-update", "alpine", "--severity", "LOW", "debian:buster"},
			logs: []string{
				"--only-update, --refresh and --auto-refresh are unnecessary and ignored now. These commands will be removed in the next version.",
			},
			want: Config{
				ReportConfig: config.ReportConfig{
					Severities: []dbTypes.Severity{dbTypes.SeverityLow},
					Output:     os.Stdout,
					VulnType:   []string{"os", "library"},
				},
				ArtifactConfig: config.ArtifactConfig{
					Target: "debian:buster",
				},
				onlyUpdate: "alpine",
			},
		},
		{
			name: "invalid option combination: --template enabled without --format",
			args: []string{"--template", "@contrib/gitlab.tpl", "gitlab/gitlab-ce:12.7.2-ce.0"},
			logs: []string{
				"--template is ignored because --format template is not specified. Use --template option with --format template option.",
			},
			want: Config{
				ReportConfig: config.ReportConfig{
					Severities: []dbTypes.Severity{dbTypes.SeverityCritical},
					Output:     os.Stdout,
					VulnType:   []string{"os", "library"},
					Template:   "@contrib/gitlab.tpl",
				},
				ArtifactConfig: config.ArtifactConfig{
					Target: "gitlab/gitlab-ce:12.7.2-ce.0",
				},
			},
		},
		{
			name: "invalid option combination: --template and --format json",
			args: []string{"--format", "json", "--template", "@contrib/gitlab.tpl", "gitlab/gitlab-ce:12.7.2-ce.0"},
			logs: []string{
				"--template is ignored because --format json is specified. Use --template option with --format template option.",
			},
			want: Config{
				ReportConfig: config.ReportConfig{
					Severities: []dbTypes.Severity{dbTypes.SeverityCritical},
					Output:     os.Stdout,
					VulnType:   []string{"os", "library"},
					Template:   "@contrib/gitlab.tpl",
					Format:     "json",
				},
				ArtifactConfig: config.ArtifactConfig{
					Target: "gitlab/gitlab-ce:12.7.2-ce.0",
				},
			},
		},
		{
			name: "invalid option combination: --format template without --template",
			args: []string{"--format", "template", "--severity", "MEDIUM", "gitlab/gitlab-ce:12.7.2-ce.0"},
			logs: []string{
				"--format template is ignored because --template not is specified. Specify --template option when you use --format template.",
			},
			want: Config{
				ReportConfig: config.ReportConfig{
					Severities: []dbTypes.Severity{dbTypes.SeverityMedium},
					Output:     os.Stdout,
					VulnType:   []string{"os", "library"},
					Format:     "template",
				},
				ArtifactConfig: config.ArtifactConfig{
					Target: "gitlab/gitlab-ce:12.7.2-ce.0",
				},
			},
		},
		{
			name:    "sad: skip and download db",
			args:    []string{"--skip-update", "--download-db-only", "alpine:3.10"},
			wantErr: "--skip-update and --download-db-only options can not be specified both",
		},
		{
			name: "sad: multiple image names",
			args: []string{"centos:7", "alpine:3.10"},
			logs: []string{
				"multiple targets cannot be specified",
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
			set.Bool("quiet", false, "")
			set.Bool("no-progress", false, "")
			set.Bool("reset", false, "")
			set.Bool("skip-update", false, "")
			set.Bool("download-db-only", false, "")
			set.Bool("auto-refresh", false, "")
			set.String("severity", "CRITICAL", "")
			set.String("vuln-type", "os,library", "")
			set.String("only-update", "", "")
			set.String("template", "", "")
			set.String("format", "", "")

			ctx := cli.NewContext(app, set, nil)
			_ = set.Parse(tt.args)

			c, err := New(ctx)
			require.NoError(t, err, err)

			c.GlobalConfig.Logger = logger.Sugar()
			err = c.Init()

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

			tt.want.GlobalConfig.Context = ctx
			tt.want.GlobalConfig.Logger = logger.Sugar()
			assert.Equal(t, tt.want, c, tt.name)
		})
	}
}
