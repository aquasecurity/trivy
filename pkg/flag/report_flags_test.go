package flag_test

import (
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"os"
	"testing"
)

func TestReportFlags_ToOptions(t *testing.T) {
	type fields struct {
		format         string
		template       string
		dependencyTree bool
		listAllPkgs    bool
		ignoreUnfixed  bool
		ignoreFile     string
		exitCode       int
		ignorePolicy   string
		output         string
		severities     string

		debug bool
	}
	tests := []struct {
		name     string
		fields   fields
		want     flag.ReportOptions
		wantLogs []string
	}{
		{
			name:   "happy default (without flags)",
			fields: fields{},
			want: flag.ReportOptions{
				Output: os.Stdout,
			},
		},
		{
			name: "happy path with an unknown severity",
			fields: fields{
				severities: "CRITICAL,INVALID",
			},
			want: flag.ReportOptions{
				Output: os.Stdout,
				Severities: []dbTypes.Severity{
					dbTypes.SeverityCritical,
				},
			},
			wantLogs: []string{
				"unknown severity option: unknown severity: INVALID",
			},
		},
		{
			name: "happy path with an cyclonedx",
			fields: fields{
				severities:  "CRITICAL",
				format:      "cyclonedx",
				listAllPkgs: true,
			},
			want: flag.ReportOptions{
				Output:      os.Stdout,
				Severities:  []dbTypes.Severity{dbTypes.SeverityCritical},
				Format:      report.FormatCycloneDX,
				ListAllPkgs: true,
			},
		},
		{
			name: "happy path with an cyclonedx option list-all-pkgs is false",
			fields: fields{
				severities:  "CRITICAL",
				format:      "cyclonedx",
				listAllPkgs: false,

				debug: true,
			},
			wantLogs: []string{
				`["cyclonedx" "spdx" "spdx-json" "github"] automatically enables '--list-all-pkgs'.`,
				`Severities: ["CRITICAL"]`,
			},
			want: flag.ReportOptions{
				Output: os.Stdout,
				Severities: []dbTypes.Severity{
					dbTypes.SeverityCritical,
				},
				Format:      report.FormatCycloneDX,
				ListAllPkgs: true,
			},
		},
		{
			name: "invalid option combination: --template enabled without --format",
			fields: fields{
				template:   "@contrib/gitlab.tpl",
				severities: "LOW",
			},
			wantLogs: []string{
				"'--template' is ignored because '--format template' is not specified. Use '--template' option with '--format template' option.",
			},
			want: flag.ReportOptions{
				Output:     os.Stdout,
				Severities: []dbTypes.Severity{dbTypes.SeverityLow},
				Template:   "@contrib/gitlab.tpl",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			level := zap.WarnLevel
			if tt.fields.debug {
				level = zap.DebugLevel
			}
			core, obs := observer.New(level)
			log.Logger = zap.New(core).Sugar()

			viper.Set(flag.FormatFlag, tt.fields.format)
			viper.Set(flag.TemplateFlag, tt.fields.template)
			viper.Set(flag.DependencyTreeFlag, tt.fields.dependencyTree)
			viper.Set(flag.ListAllPkgsFlag, tt.fields.listAllPkgs)
			viper.Set(flag.IgnoreFileFlag, tt.fields.ignoreFile)
			viper.Set(flag.IgnoreUnfixedFlag, tt.fields.ignoreUnfixed)
			viper.Set(flag.ExitCodeFlag, tt.fields.exitCode)
			viper.Set(flag.IgnorePolicyFlag, tt.fields.ignorePolicy)
			viper.Set(flag.OutputFlag, tt.fields.output)
			viper.Set(flag.SeverityFlag, tt.fields.severities)

			// Assert options
			f := &flag.ReportFlags{}

			got, err := f.ToOptions(os.Stdout)
			assert.NoError(t, err)
			assert.Equalf(t, tt.want, got, "ToOptions()")

			// Assert log messages
			var gotMessages []string
			for _, entry := range obs.AllUntimed() {
				gotMessages = append(gotMessages, entry.Message)
			}
			assert.Equal(t, tt.wantLogs, gotMessages, tt.name)
		})
	}
}
