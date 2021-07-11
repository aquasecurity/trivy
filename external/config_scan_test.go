package external_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/external"
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
								ID:       "XYZ-200",
								Type:     "Docker Security Check",
								Title:    "Old FROM",
								Severity: "LOW",
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
								ID:       "XYZ-200",
								Type:     "Docker Security Check",
								Title:    "Old FROM",
								Severity: "LOW",
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
				tt.fields.policyPaths, tt.fields.dataPaths, tt.fields.namespaces)
			require.NoError(t, err)

			got, err := s.Scan(tt.inputDir)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
