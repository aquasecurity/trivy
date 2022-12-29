package external_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/external"
	_ "github.com/aquasecurity/trivy/pkg/fanal/handler/misconf"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
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
				policyPaths: []string{filepath.Join("testdata", "deny")},
				namespaces:  []string{"testdata"},
			},
			inputDir: filepath.Join("testdata", "deny"),
			want: []types.Misconfiguration{
				{
					FileType: "dockerfile",
					FilePath: "Dockerfile",
					Failures: types.MisconfResults{
						types.MisconfResult{
							Namespace: "testdata.xyz_200",
							Query:     "data.testdata.xyz_200.deny",
							Message:   "Old image",
							PolicyMetadata: types.PolicyMetadata{
								ID:                 "XYZ-200",
								Type:               "Dockerfile Security Check",
								Title:              "Old FROM",
								Description:        "Rego module: data.testdata.xyz_200",
								Severity:           "LOW",
								RecommendedActions: "",
								References:         []string(nil),
							},
							CauseMetadata: types.CauseMetadata{
								Resource:  "",
								Provider:  "Dockerfile",
								Service:   "general",
								StartLine: 1,
								EndLine:   2,
								Code: types.Code{
									Lines: []types.Line{
										{
											Number:      1,
											Content:     "FROM alpine:3.10",
											Highlighted: "\x1b[38;5;64mFROM\x1b[0m\x1b[38;5;37m alpine:3.10",
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
							}, Traces: []string(nil),
						},
					}, Warnings: types.MisconfResults(nil),
					Successes:  types.MisconfResults(nil),
					Exceptions: types.MisconfResults(nil),
					Layer: types.Layer{
						Digest: "",
						DiffID: "",
					},
				},
			},
		},
		{
			name: "allow",
			fields: fields{
				policyPaths: []string{filepath.Join("testdata", "allow")},
				namespaces:  []string{"testdata"},
			},
			inputDir: filepath.Join("testdata", "allow"),
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

			defer func() { _ = s.Close() }()

			got, err := s.Scan(tt.inputDir)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
