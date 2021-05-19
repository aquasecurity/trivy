package scanner_test

import (
	"context"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/config/scanner"
	"github.com/aquasecurity/fanal/types"
)

func TestScanner_ScanConfig(t *testing.T) {
	// only does basic tests
	// check for misconfigurations in implementations
	tests := []struct {
		name        string
		policyPaths []string
		dataPaths   []string
		configType  string
		content     interface{}
		namespaces  []string
		want        types.Misconfiguration
		wantErr     string
	}{
		{
			name:        "happy path",
			policyPaths: []string{"testdata/valid/100.rego"},
			configType:  types.Kubernetes,
			content: map[string]interface{}{
				"apiVersion": "apps/v1",
				"kind":       "Deployment",
			},
			namespaces: []string{"testdata"},
			want: types.Misconfiguration{
				FileType: "kubernetes",
				FilePath: "deployment.yaml",
				Failures: []types.MisconfResult{
					{
						Namespace: "testdata.kubernetes.id_100",
						Message:   "deny",
						PolicyMetadata: types.PolicyMetadata{
							Type:     "Kubernetes Security Check",
							Title:    "Bad Deployment",
							ID:       "ID-100",
							Severity: "HIGH",
						},
					},
				},
			},
		},
		{
			name:        "happy path with multiple policies",
			policyPaths: []string{"testdata/valid/"},
			configType:  types.Kubernetes,
			content: map[string]interface{}{
				"apiVersion": "apps/v1",
				"kind":       "Deployment",
			},
			namespaces: []string{"testdata"},
			want: types.Misconfiguration{
				FileType:  "kubernetes",
				FilePath:  "deployment.yaml",
				Successes: types.MisconfResults(nil),
				Warnings:  types.MisconfResults(nil),
				Failures: types.MisconfResults{
					types.MisconfResult{
						Namespace:      "testdata.docker.id_300",
						Message:        "deny",
						PolicyMetadata: types.PolicyMetadata{ID: "N/A", Type: "N/A", Title: "N/A", Severity: "UNKNOWN"},
					},
					types.MisconfResult{
						Namespace:      "testdata.kubernetes.id_100",
						Message:        "deny",
						PolicyMetadata: types.PolicyMetadata{ID: "ID-100", Type: "Kubernetes Security Check", Title: "Bad Deployment", Severity: "HIGH"},
					},
					types.MisconfResult{
						Namespace:      "testdata.kubernetes.id_200",
						Message:        "deny",
						PolicyMetadata: types.PolicyMetadata{ID: "ID-200", Type: "Kubernetes Security Check", Title: "Bad Deployment", Severity: "CRITICAL"},
					},
				}, Exceptions: types.MisconfResults(nil), Layer: types.Layer{Digest: "", DiffID: ""},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := scanner.New(tt.namespaces, tt.policyPaths, tt.dataPaths)
			require.NoError(t, err)

			got, err := s.ScanConfigs(context.Background(), []types.Config{{tt.configType, "deployment.yaml", tt.content}})
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.Nil(t, got)
				return
			}

			sort.Slice(got[0].Failures, func(i, j int) bool {
				return got[0].Failures[i].Namespace < got[0].Failures[j].Namespace
			})

			require.NoError(t, err)
			assert.Equal(t, tt.want, got[0])
		})
	}
}
