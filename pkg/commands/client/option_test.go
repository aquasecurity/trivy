package client

import (
	"flag"
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/commands/option"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestConfig_Init(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		logs    []string
		want    Option
		wantErr string
	}{
		{
			name: "happy path",
			args: []string{"--severity", "CRITICAL", "--vuln-type", "os", "--quiet", "alpine:3.10"},
			want: Option{
				GlobalOption: option.GlobalOption{
					Quiet: true,
				},
				ArtifactOption: option.ArtifactOption{
					Target: "alpine:3.10",
				},
				ReportOption: option.ReportOption{
					Severities:     []dbTypes.Severity{dbTypes.SeverityCritical},
					VulnType:       []string{types.VulnTypeOS},
					SecurityChecks: []string{types.SecurityCheckVulnerability},
					Output:         os.Stdout,
				},
				CustomHeaders: http.Header{},
			},
		},
		{
			name: "config scanning",
			args: []string{"--severity", "CRITICAL", "--security-checks", "config", "--quiet", "alpine:3.10"},
			want: Option{
				GlobalOption: option.GlobalOption{
					Quiet: true,
				},
				ArtifactOption: option.ArtifactOption{
					Target: "alpine:3.10",
				},
				ReportOption: option.ReportOption{
					Severities:     []dbTypes.Severity{dbTypes.SeverityCritical},
					VulnType:       []string{types.VulnTypeOS, types.VulnTypeLibrary},
					SecurityChecks: []string{types.SecurityCheckConfig},
					Output:         os.Stdout,
				},
				CustomHeaders: http.Header{},
			},
		},
		{
			name: "happy path with token and token header",
			args: []string{"--token", "secret", "--token-header", "X-Trivy-Token", "alpine:3.11"},
			want: Option{
				ReportOption: option.ReportOption{
					Severities:     []dbTypes.Severity{dbTypes.SeverityCritical},
					Output:         os.Stdout,
					VulnType:       []string{types.VulnTypeOS, types.VulnTypeLibrary},
					SecurityChecks: []string{types.SecurityCheckVulnerability},
				},
				ArtifactOption: option.ArtifactOption{
					Target: "alpine:3.11",
				},
				token:       "secret",
				tokenHeader: "X-Trivy-Token",
				CustomHeaders: http.Header{
					"X-Trivy-Token": []string{"secret"},
				},
			},
		},
		{
			name: "happy path with good custom headers",
			args: []string{"--custom-headers", "foo:bar", "alpine:3.11"},
			want: Option{
				ReportOption: option.ReportOption{
					Severities:     []dbTypes.Severity{dbTypes.SeverityCritical},
					Output:         os.Stdout,
					VulnType:       []string{types.VulnTypeOS, types.VulnTypeLibrary},
					SecurityChecks: []string{types.SecurityCheckVulnerability},
				},
				ArtifactOption: option.ArtifactOption{
					Target: "alpine:3.11",
				},
				customHeaders: []string{"foo:bar"},
				CustomHeaders: http.Header{
					"Foo": []string{"bar"},
				},
			},
		},
		{
			name: "happy path with bad custom headers",
			args: []string{"--custom-headers", "foobaz", "alpine:3.11"},
			want: Option{
				ReportOption: option.ReportOption{
					Severities:     []dbTypes.Severity{dbTypes.SeverityCritical},
					Output:         os.Stdout,
					VulnType:       []string{types.VulnTypeOS, types.VulnTypeLibrary},
					SecurityChecks: []string{types.SecurityCheckVulnerability},
				},
				ArtifactOption: option.ArtifactOption{
					Target: "alpine:3.11",
				},
				customHeaders: []string{"foobaz"},
				CustomHeaders: http.Header{},
			},
		},
		{
			name: "happy path with an unknown severity",
			args: []string{"--severity", "CRITICAL,INVALID", "centos:7"},
			logs: []string{
				"unknown severity option: unknown severity: INVALID",
			},
			want: Option{
				ReportOption: option.ReportOption{
					Severities:     []dbTypes.Severity{dbTypes.SeverityCritical, dbTypes.SeverityUnknown},
					Output:         os.Stdout,
					VulnType:       []string{types.VulnTypeOS, types.VulnTypeLibrary},
					SecurityChecks: []string{types.SecurityCheckVulnerability},
				},
				ArtifactOption: option.ArtifactOption{
					Target: "centos:7",
				},
				CustomHeaders: http.Header{},
			},
		},
		{
			name: "invalid option combination: --template enabled without --format",
			args: []string{"--template", "@contrib/gitlab.tpl", "gitlab/gitlab-ce:12.7.2-ce.0"},
			logs: []string{
				"--template is ignored because --format template is not specified. Use --template option with --format template option.",
			},
			want: Option{
				ReportOption: option.ReportOption{
					Severities:     []dbTypes.Severity{dbTypes.SeverityCritical},
					Output:         os.Stdout,
					VulnType:       []string{types.VulnTypeOS, types.VulnTypeLibrary},
					SecurityChecks: []string{types.SecurityCheckVulnerability},
					Template:       "@contrib/gitlab.tpl",
				},
				ArtifactOption: option.ArtifactOption{
					Target: "gitlab/gitlab-ce:12.7.2-ce.0",
				},
				CustomHeaders: http.Header{},
			},
		},
		{
			name: "invalid option combination: --template and --format json",
			args: []string{"--format", "json", "--template", "@contrib/gitlab.tpl", "gitlab/gitlab-ce:12.7.2-ce.0"},
			logs: []string{
				"--template is ignored because --format json is specified. Use --template option with --format template option.",
			},
			want: Option{
				ReportOption: option.ReportOption{
					Severities:     []dbTypes.Severity{dbTypes.SeverityCritical},
					Output:         os.Stdout,
					VulnType:       []string{types.VulnTypeOS, types.VulnTypeLibrary},
					SecurityChecks: []string{types.SecurityCheckVulnerability},
					Template:       "@contrib/gitlab.tpl",
					Format:         "json",
				},
				ArtifactOption: option.ArtifactOption{
					Target: "gitlab/gitlab-ce:12.7.2-ce.0",
				},
				CustomHeaders: http.Header{},
			},
		},
		{
			name: "invalid option combination: --format template without --template",
			args: []string{"--format", "template", "--severity", "MEDIUM", "gitlab/gitlab-ce:12.7.2-ce.0"},
			logs: []string{
				"--format template is ignored because --template not is specified. Specify --template option when you use --format template.",
			},
			want: Option{
				ReportOption: option.ReportOption{
					Severities:     []dbTypes.Severity{dbTypes.SeverityMedium},
					Output:         os.Stdout,
					VulnType:       []string{types.VulnTypeOS, types.VulnTypeLibrary},
					SecurityChecks: []string{types.SecurityCheckVulnerability},
					Format:         "template",
				},
				ArtifactOption: option.ArtifactOption{
					Target: "gitlab/gitlab-ce:12.7.2-ce.0",
				},
				CustomHeaders: http.Header{},
			},
		},
		{
			name: "invalid option combination: --format template without --template",
			args: []string{"--format", "template", "--severity", "MEDIUM", "gitlab/gitlab-ce:12.7.2-ce.0"},
			logs: []string{
				"--format template is ignored because --template not is specified. Specify --template option when you use --format template.",
			},
			want: Option{
				ReportOption: option.ReportOption{
					Severities:     []dbTypes.Severity{dbTypes.SeverityMedium},
					Output:         os.Stdout,
					VulnType:       []string{types.VulnTypeOS, types.VulnTypeLibrary},
					SecurityChecks: []string{types.SecurityCheckVulnerability},
					Format:         "template",
				},
				ArtifactOption: option.ArtifactOption{
					Target: "gitlab/gitlab-ce:12.7.2-ce.0",
				},
				CustomHeaders: http.Header{},
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			core, obs := observer.New(zap.InfoLevel)
			logger := zap.New(core)

			app := cli.NewApp()
			set := flag.NewFlagSet("test", 0)
			set.Bool("quiet", false, "")
			set.Bool("no-progress", false, "")
			set.Bool("clear-cache", false, "")
			set.String("severity", "CRITICAL", "")
			set.String("vuln-type", "os,library", "")
			set.String("security-checks", "vuln", "")
			set.String("template", "", "")
			set.String("format", "", "")
			set.String("token", "", "")
			set.String("token-header", "", "")
			set.Var(&cli.StringSlice{}, "custom-headers", "")

			ctx := cli.NewContext(app, set, nil)
			_ = set.Parse(tt.args)

			c, err := NewOption(ctx)
			require.NoError(t, err, err)

			c.GlobalOption.Logger = logger.Sugar()
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
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
				return
			default:
				assert.NoError(t, err, tt.name)
			}

			tt.want.GlobalOption.Context = ctx
			tt.want.GlobalOption.Logger = logger.Sugar()
			assert.Equal(t, tt.want, c, tt.name)
		})
	}
}

func Test_splitCustomHeaders(t *testing.T) {
	type args struct {
		headers []string
	}
	tests := []struct {
		name string
		args args
		want http.Header
	}{
		{
			name: "happy path",
			args: args{
				headers: []string{"x-api-token:foo bar", "Authorization:user:password"},
			},
			want: http.Header{
				"X-Api-Token":   []string{"foo bar"},
				"Authorization": []string{"user:password"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitCustomHeaders(tt.args.headers)
			assert.Equal(t, tt.want, got)
		})
	}
}
