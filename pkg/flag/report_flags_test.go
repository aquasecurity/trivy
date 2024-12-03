package flag_test

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/compliance/spec"
	"github.com/aquasecurity/trivy/pkg/flag"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestReportFlagGroup_ToOptions(t *testing.T) {
	type fields struct {
		format           types.Format
		template         string
		dependencyTree   bool
		listAllPkgs      bool
		ignoreUnfixed    bool
		ignoreFile       string
		exitCode         int
		exitOnEOSL       bool
		ignorePolicy     string
		output           string
		outputPluginArgs string
		severities       string
		compliance       string
		debug            bool
		pkgTypes         string
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
			name: "happy path with an cyclonedx",
			fields: fields{
				severities: "CRITICAL",
				format:     "cyclonedx",
			},
			want: flag.ReportOptions{
				Severities: []dbTypes.Severity{dbTypes.SeverityCritical},
				Format:     types.FormatCycloneDX,
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
			name: "invalid option combination: --list-all-pkgs with --format table",
			fields: fields{
				format:      "table",
				severities:  "LOW",
				listAllPkgs: true,
			},
			wantLogs: []string{
				`"--list-all-pkgs" is only valid for the JSON format, for other formats a list of packages is automatically included.`,
			},
			want: flag.ReportOptions{
				Format:      "table",
				Severities:  []dbTypes.Severity{dbTypes.SeverityLow},
				ListAllPkgs: true,
			},
		},
		{
			name: "happy path with output plugin args",
			fields: fields{
				output:           "plugin=count",
				outputPluginArgs: "--publish-after 2023-10-01 --publish-before 2023-10-02",
			},
			want: flag.ReportOptions{
				Output: "plugin=count",
				OutputPluginArgs: []string{
					"--publish-after",
					"2023-10-01",
					"--publish-before",
					"2023-10-02",
				},
			},
		},
		{
			name: "happy path with compliance",
			fields: fields{
				compliance: "@testdata/example-spec.yaml",
				severities: dbTypes.SeverityLow.String(),
			},
			want: flag.ReportOptions{
				Compliance: spec.ComplianceSpec{
					Spec: iacTypes.Spec{
						ID:          "0001",
						Title:       "my-custom-spec",
						Description: "My fancy spec",
						Version:     "1.2",
						Controls: []iacTypes.Control{
							{
								ID:          "1.1",
								Name:        "Unencrypted S3 bucket",
								Description: "S3 Buckets should be encrypted to protect the data that is stored within them if access is compromised.",
								Checks: []iacTypes.SpecCheck{
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
			t.Cleanup(viper.Reset)

			level := log.LevelWarn
			if tt.fields.debug {
				level = log.LevelDebug
			}
			out := newLogger(level)

			setValue(flag.FormatFlag.ConfigName, string(tt.fields.format))
			setValue(flag.TemplateFlag.ConfigName, tt.fields.template)
			setValue(flag.DependencyTreeFlag.ConfigName, tt.fields.dependencyTree)
			setValue(flag.ListAllPkgsFlag.ConfigName, tt.fields.listAllPkgs)
			setValue(flag.IgnoreFileFlag.ConfigName, tt.fields.ignoreFile)
			setValue(flag.IgnoreUnfixedFlag.ConfigName, tt.fields.ignoreUnfixed)
			setValue(flag.IgnorePolicyFlag.ConfigName, tt.fields.ignorePolicy)
			setValue(flag.ExitCodeFlag.ConfigName, tt.fields.exitCode)
			setValue(flag.ExitOnEOLFlag.ConfigName, tt.fields.exitOnEOSL)
			setValue(flag.OutputFlag.ConfigName, tt.fields.output)
			setValue(flag.OutputPluginArgFlag.ConfigName, tt.fields.outputPluginArgs)
			setValue(flag.SeverityFlag.ConfigName, tt.fields.severities)
			setValue(flag.ComplianceFlag.ConfigName, tt.fields.compliance)

			// Assert options
			f := &flag.ReportFlagGroup{
				Format:          flag.FormatFlag.Clone(),
				Template:        flag.TemplateFlag.Clone(),
				DependencyTree:  flag.DependencyTreeFlag.Clone(),
				ListAllPkgs:     flag.ListAllPkgsFlag.Clone(),
				IgnoreFile:      flag.IgnoreFileFlag.Clone(),
				IgnorePolicy:    flag.IgnorePolicyFlag.Clone(),
				ExitCode:        flag.ExitCodeFlag.Clone(),
				ExitOnEOL:       flag.ExitOnEOLFlag.Clone(),
				Output:          flag.OutputFlag.Clone(),
				OutputPluginArg: flag.OutputPluginArgFlag.Clone(),
				Severity:        flag.SeverityFlag.Clone(),
				Compliance:      flag.ComplianceFlag.Clone(),
			}

			got, err := f.ToOptions()
			require.NoError(t, err)
			assert.EqualExportedValuesf(t, tt.want, got, "ToOptions()")

			// Assert log messages
			assert.Equal(t, tt.wantLogs, out.Messages(), tt.name)
		})
	}

	t.Run("Error on non existing ignore file", func(t *testing.T) {
		t.Cleanup(viper.Reset)

		setValue(flag.IgnoreFileFlag.ConfigName, "doesntexist")
		f := &flag.ReportFlagGroup{
			IgnoreFile: flag.IgnoreFileFlag.Clone(),
		}

		_, err := f.ToOptions()
		assert.ErrorContains(t, err, "ignore file not found: doesntexist")
	})
}
