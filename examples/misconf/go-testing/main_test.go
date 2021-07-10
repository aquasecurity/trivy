package main_test

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/external"
	"github.com/aquasecurity/fanal/types"
)

func TestPolicy(t *testing.T) {
	type fields struct {
		policyPaths []string
		dataPaths   []string
		namespaces  []string
	}
	tests := []struct {
		name   string
		fields fields
		input  string
		want   []types.Misconfiguration
	}{
		{
			name:  "disallowed ports",
			input: "configs/",
			fields: fields{
				policyPaths: []string{"policy"},
				dataPaths:   []string{"data"},
				namespaces:  []string{"user"},
			},
			want: []types.Misconfiguration{
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.allowed",
					Successes: types.MisconfResults{
						{
							Namespace: "user.dockerfile.ID002",
							PolicyMetadata: types.PolicyMetadata{
								ID:          "ID002",
								Type:        "Docker Custom Check",
								Title:       "Disallowed ports exposed",
								Description: "Vulnerable ports are exposed.",
								Severity:    "HIGH",
							},
						},
					},
				},
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.denied",
					Failures: types.MisconfResults{
						{
							Namespace: "user.dockerfile.ID002",
							Message:   "Port 23 should not be exposed",
							PolicyMetadata: types.PolicyMetadata{
								ID:          "ID002",
								Type:        "Docker Custom Check",
								Title:       "Disallowed ports exposed",
								Description: "Vulnerable ports are exposed.",
								Severity:    "HIGH",
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

			got, err := s.Scan(tt.input)
			require.NoError(t, err)

			// For consistency
			sort.Slice(got, func(i, j int) bool {
				return got[i].FilePath < got[j].FilePath
			})

			// Assert the scan result
			assert.Equal(t, tt.want, got)
		})
	}
}
