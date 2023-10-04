package flag_test

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/compliance/spec"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestReportFlagGroup_ToOptions(t *testing.T) {
	type fields struct {
		format         types.Format
		template       string
		dependencyTree bool
		listAllPkgs    bool
		ignoreUnfixed  bool
		ignoreFile     string
		exitCode       int
		exitOnEOSL     bool
		ignorePolicy   string
		output         string
		severities     string
		compliane      string

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
			want:   flag.ReportOptions{},
		},
		{
			name: "list-all-pkgs warning",
			fields: fields{
				listAllPkgs: true,
			},
			want: flag.ReportOptions{},
			wantLogs: []string{
				`'--list-all-pkgs' option has been removed. Use '--scanners pkg' to show all packages found.`,
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
				Severities: []dbTypes.Severity{dbTypes.SeverityLow},
				Template:   "@contrib/gitlab.tpl",
			},
		},
		{
			name: "invalid option combination: --template and --format json",
			fields: fields{
				format:     "json",
				template:   "@contrib/gitlab.tpl",
				severities: "LOW",
			},
			wantLogs: []string{
				"'--template' is ignored because '--format json' is specified. Use '--template' option with '--format template' option.",
			},
			want: flag.ReportOptions{
				Format:     "json",
				Severities: []dbTypes.Severity{dbTypes.SeverityLow},
				Template:   "@contrib/gitlab.tpl",
			},
		},
		{
			name: "invalid option combination: --format template without --template",
			fields: fields{
				format:     "template",
				severities: "LOW",
			},
			wantLogs: []string{
				"'--format template' is ignored because '--template' is not specified. Specify '--template' option when you use '--format template'.",
			},
			want: flag.ReportOptions{
				Format:     "template",
				Severities: []dbTypes.Severity{dbTypes.SeverityLow},
			},
		},
		{
			name: "happy path with compliance",
			fields: fields{
				compliane:  "@testdata/example-spec.yaml",
				severities: dbTypes.SeverityLow.String(),
			},
			want: flag.ReportOptions{
				Compliance: spec.ComplianceSpec{
					Spec: defsecTypes.Spec{
						ID:          "0001",
						Title:       "my-custom-spec",
						Description: "My fancy spec",
						Version:     "1.2",
						Controls: []defsecTypes.Control{
							{
								ID:          "1.1",
								Name:        "Unencrypted S3 bucket",
								Description: "S3 Buckets should be encrypted to protect the data that is stored within them if access is compromised.",
								Checks: []defsecTypes.SpecCheck{
									{ID: "AVD-AWS-0088"},
								},
								Severity: "HIGH",
							},
						},
					},
				},
				Severities: []dbTypes.Severity{dbTypes.SeverityLow},
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

			viper.Set(flag.FormatFlag.ConfigName, string(tt.fields.format))
			viper.Set(flag.TemplateFlag.ConfigName, tt.fields.template)
			viper.Set(flag.DependencyTreeFlag.ConfigName, tt.fields.dependencyTree)
			viper.Set(flag.ListAllPkgsFlag.ConfigName, tt.fields.listAllPkgs)
			viper.Set(flag.IgnoreFileFlag.ConfigName, tt.fields.ignoreFile)
			viper.Set(flag.IgnoreUnfixedFlag.ConfigName, tt.fields.ignoreUnfixed)
			viper.Set(flag.IgnorePolicyFlag.ConfigName, tt.fields.ignorePolicy)
			viper.Set(flag.ExitCodeFlag.ConfigName, tt.fields.exitCode)
			viper.Set(flag.ExitOnEOLFlag.ConfigName, tt.fields.exitOnEOSL)
			viper.Set(flag.OutputFlag.ConfigName, tt.fields.output)
			viper.Set(flag.SeverityFlag.ConfigName, tt.fields.severities)
			viper.Set(flag.ComplianceFlag.ConfigName, tt.fields.compliane)

			// Assert options
			f := &flag.ReportFlagGroup{
				Format:         &flag.FormatFlag,
				Template:       &flag.TemplateFlag,
				DependencyTree: &flag.DependencyTreeFlag,
				IgnoreFile:     &flag.IgnoreFileFlag,
				IgnorePolicy:   &flag.IgnorePolicyFlag,
				ExitCode:       &flag.ExitCodeFlag,
				ExitOnEOL:      &flag.ExitOnEOLFlag,
				Output:         &flag.OutputFlag,
				Severity:       &flag.SeverityFlag,
				Compliance:     &flag.ComplianceFlag,
			}

			got, err := f.ToOptions()
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
