package external_test

import (
	"testing"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/external"
	_ "github.com/aquasecurity/fanal/handler/misconf"
	"github.com/aquasecurity/fanal/types"
)

func TestConfigScanner_Scan(t *testing.T) {
	type fields struct {
		policyPaths []string
		dataPaths   []string
		namespaces  []string
	}
	tests := []struct {
		name     string
		fields   fields
		inputDir string
		want     []types.Misconfiguration
	}{
		{
			name: "deny",
			fields: fields{
				policyPaths: []string{"testdata/deny"},
				namespaces:  []string{"testdata"},
			},
			inputDir: "testdata/deny",
			want: []types.Misconfiguration{
				{
					FileType: "dockerfile",
					FilePath: "Dockerfile",
					Failures: types.MisconfResults{
						{
							Namespace: "testdata.xyz_200",
							Query:     "data.testdata.xyz_200.deny",
							Message:   "Old image",
							PolicyMetadata: types.PolicyMetadata{
								ID:          "XYZ-200",
								Type:        "Dockerfile Security Check",
								Title:       "Old FROM",
								Description: "Rego module: data.testdata.xyz_200",
								Severity:    "LOW",
							},
							CauseMetadata: types.CauseMetadata{
								Resource:  "",
								Provider:  "Dockerfile",
								Service:   "general",
								StartLine: 1,
								EndLine:   2,
								Code: scan.Code{
									Lines: []scan.Line{
										{
											Number:      1,
											Content:     "FROM alpine:3.10",
											Highlighted: "\x1b\x1b[38;5;64mFROM\x1b\x1b[0m\x1b\x1b[38;5;37m alpine:3.10\x1b",
											IsCause:     true,
											Annotation:  "",
											Truncated:   false,
											FirstCause:  true,
											LastCause:   false,
										},
										{
											Number:      2,
											Content:     "",
											Highlighted: "\x1b[0m",
											IsCause:     true,
											Annotation:  "",
											Truncated:   false,
											FirstCause:  false,
											LastCause:   true,
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "allow",
			fields: fields{
				policyPaths: []string{"testdata/allow"},
				namespaces:  []string{"testdata"},
			},
			inputDir: "testdata/allow",
			want: []types.Misconfiguration{
				{
					FileType: "dockerfile",
					FilePath: "Dockerfile",
					Successes: types.MisconfResults{
						{
							Namespace: "testdata.xyz_200",
							Query:     "data.testdata.xyz_200.deny",
							PolicyMetadata: types.PolicyMetadata{
								ID:          "XYZ-200",
								Type:        "Dockerfile Security Check",
								Title:       "Old FROM",
								Description: "Rego module: data.testdata.xyz_200",
								Severity:    "LOW",
							},
							CauseMetadata: types.CauseMetadata{
								Resource:  "",
								Provider:  "Dockerfile",
								Service:   "general",
								StartLine: 0,
								EndLine:   0,
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := external.NewConfigScanner(t.TempDir(),
				tt.fields.policyPaths, tt.fields.dataPaths, tt.fields.namespaces, false)
			require.NoError(t, err)

			got, err := s.Scan(tt.inputDir)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
