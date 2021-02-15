package config

import (
	"flag"
	"os"
	"testing"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestReportReportConfig_Init(t *testing.T) {
	type fields struct {
		output        string
		format        string
		template      string
		vulnType      string
		severities    string
		IgnoreFile    string
		IgnoreUnfixed bool
		ExitCode      int
		VulnType      []string
		Severities    []dbTypes.Severity
		Formats       map[string]MappedFormat
	}
	tests := []struct {
		name    string
		fields  fields
		args    []string
		logs    []string
		want    ReportConfig
		wantErr string
	}{
		{
			name: "happy path",
			fields: fields{
				severities: "CRITICAL",
				vulnType:   "os",
			},
			args: []string{"alpine:3.10"},
			want: ReportConfig{
				Severities: []dbTypes.Severity{dbTypes.SeverityCritical},
				VulnType:   []string{"os"},
				Formats: map[string]MappedFormat{
					"table": MappedFormat{
						Output:   os.Stdout,
						Template: "",
					},
				},
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
			want: ReportConfig{
				Severities: []dbTypes.Severity{dbTypes.SeverityCritical, dbTypes.SeverityUnknown},
				VulnType:   []string{"os", "library"},
				Formats: map[string]MappedFormat{
					"table": MappedFormat{
						Output:   os.Stdout,
						Template: "",
					},
				},
			},
		},
		{
			name: "invalid option combination: --format template without --template",
			fields: fields{
				format:     "template",
				severities: "LOW",
			},
			args: []string{"gitlab/gitlab-ce:12.7.2-ce.0"},
			logs: []string{
				"--format template is ignored because --template is not specified. Specify --template option when you use --format template.",
			},
			want: ReportConfig{
				Severities: []dbTypes.Severity{dbTypes.SeverityLow},
				VulnType:   []string{""},
				Formats:    nil,
			},
		},
		{
			name: "invalid option combination: --template enabled without --format",
			fields: fields{
				template:   "@contrib/gitlab.tpl",
				severities: "LOW",
			},
			args: []string{"gitlab/gitlab-ce:12.7.2-ce.0"},
			logs: []string{
				"--template is ignored because --format template is not specified. Use --template option with --format template option.",
			},
			want: ReportConfig{
				Severities: []dbTypes.Severity{dbTypes.SeverityLow},
				VulnType:   []string{""},
				Formats: map[string]MappedFormat{
					"table": MappedFormat{
						Output:   os.Stdout,
						Template: "",
					},
				},
			},
		},
		{
			name: "invalid option combination: --template and --format json",
			fields: fields{
				format:     "json",
				template:   "@contrib/gitlab.tpl",
				severities: "LOW",
			},
			args: []string{"gitlab/gitlab-ce:12.7.2-ce.0"},
			logs: []string{
				"--template is ignored because --format [json] is specified. Use --template option with --format template option.",
			},
			want: ReportConfig{
				Severities: []dbTypes.Severity{dbTypes.SeverityLow},
				VulnType:   []string{""},
				Formats: map[string]MappedFormat{
					"json": MappedFormat{
						Output:   os.Stdout,
						Template: "",
					},
				},
			},
		},
		{
			name: "multi-format: invalid option combination: --template enabled without matching --format template",
			fields: fields{
				format:     "table,json",
				template:   "@contrib/gitlab.tpl",
				severities: "LOW",
			},
			args: []string{"gitlab/gitlab-ce:12.7.2-ce.0"},
			logs: []string{
				"--template is ignored because --format [table json] is specified. Use --template option with --format template option.",
			},
			want: ReportConfig{
				Severities: []dbTypes.Severity{dbTypes.SeverityLow},
				VulnType:   []string{""},
				Formats: map[string]MappedFormat{
					"table": MappedFormat{
						Output:   os.Stdout,
						Template: "",
					},
					"json": MappedFormat{
						Output:   os.Stdout,
						Template: "",
					},
				},
			},
		},
		{
			name: "multi-format: invalid option combination: --format template without --template",
			fields: fields{
				format:     "table,template",
				severities: "LOW",
			},
			args: []string{"gitlab/gitlab-ce:12.7.2-ce.0"},
			logs: []string{
				"--format template is ignored because --template is not specified. Specify --template option when you use --format template.",
			},
			want: ReportConfig{
				Severities: []dbTypes.Severity{dbTypes.SeverityLow},
				VulnType:   []string{""},
				Formats: map[string]MappedFormat{
					"table": MappedFormat{
						Output:   os.Stdout,
						Template: "",
					},
				},
			},
		},
		{
			name: "multi-format: invalid option combination: more than one --format template",
			fields: fields{
				format:     "template,template",
				template:   "@contrib/gitlab.tpl",
				severities: "LOW",
			},
			args: []string{"gitlab/gitlab-ce:12.7.2-ce.0"},
			logs: []string{
				"--format template is ignored because it has been specified.",
			},
			want: ReportConfig{
				Severities: []dbTypes.Severity{dbTypes.SeverityLow},
				VulnType:   []string{""},
				Formats: map[string]MappedFormat{
					"template": MappedFormat{
						Output:   os.Stdout,
						Template: "@contrib/gitlab.tpl",
					},
				},
			},
		},
		{
			name: "multi-format: valid option combination",
			fields: fields{
				format:     "table,template,json",
				template:   "@contrib/gitlab.tpl,@contrib/junit.tpl",
				severities: "LOW",
			},
			args: []string{"gitlab/gitlab-ce:12.7.2-ce.0"},
			want: ReportConfig{
				Severities: []dbTypes.Severity{dbTypes.SeverityLow},
				VulnType:   []string{""},
				Formats: map[string]MappedFormat{
					"table": MappedFormat{
						Output:   os.Stdout,
						Template: "",
					},
					"template": MappedFormat{
						Output:   os.Stdout,
						Template: "@contrib/gitlab.tpl",
					},
					"json": MappedFormat{
						Output:   os.Stdout,
						Template: "",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			core, obs := observer.New(zap.InfoLevel)
			logger := zap.New(core)

			set := flag.NewFlagSet("test", 0)
			_ = set.Parse(tt.args)

			c := &ReportConfig{
				format:        tt.fields.format,
				output:        tt.fields.output,
				template:      tt.fields.template,
				vulnType:      tt.fields.vulnType,
				severities:    tt.fields.severities,
				IgnoreFile:    tt.fields.IgnoreFile,
				IgnoreUnfixed: tt.fields.IgnoreUnfixed,
				ExitCode:      tt.fields.ExitCode,
				Formats:       tt.fields.Formats,
			}

			err := c.Init(logger.Sugar())

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
