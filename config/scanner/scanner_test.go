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
		rootDir     string
		policyPaths []string
		dataPaths   []string
		configs     []types.Config
		namespaces  []string
		want        types.Misconfiguration
		wantErr     string
	}{
		{
			name:        "happy path",
			rootDir:     "testdata",
			policyPaths: []string{"testdata/valid/100.rego"},
			namespaces:  []string{"testdata"},
			configs: []types.Config{
				{
					Type:     types.Kubernetes,
					FilePath: "deployment.yaml",
					Content: map[string]interface{}{
						"apiVersion": "apps/v1",
						"kind":       "Deployment",
					},
				},
			},
			want: types.Misconfiguration{
				FileType: types.Kubernetes,
				FilePath: "deployment.yaml",
				Failures: []types.MisconfResult{
					{
						Namespace: "testdata.kubernetes.id_100",
						Query:     "data.testdata.kubernetes.id_100.deny",
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
			namespaces:  []string{"testdata"},
			configs: []types.Config{
				{
					Type:     types.Kubernetes,
					FilePath: "deployment.yaml",
					Content: map[string]interface{}{
						"apiVersion": "apps/v1",
						"kind":       "Deployment",
					},
				},
			},
			want: types.Misconfiguration{
				FileType:  types.Kubernetes,
				FilePath:  "deployment.yaml",
				Successes: types.MisconfResults(nil),
				Warnings:  types.MisconfResults(nil),
				Failures: types.MisconfResults{
					types.MisconfResult{
						Namespace:      "testdata.docker.id_300",
						Query:          "data.testdata.docker.id_300.deny",
						Message:        "deny",
						PolicyMetadata: types.PolicyMetadata{ID: "N/A", Type: "N/A", Title: "N/A", Severity: "UNKNOWN"},
					},
					types.MisconfResult{
						Namespace:      "testdata.kubernetes.id_100",
						Query:          "data.testdata.kubernetes.id_100.deny",
						Message:        "deny",
						PolicyMetadata: types.PolicyMetadata{ID: "ID-100", Type: "Kubernetes Security Check", Title: "Bad Deployment", Severity: "HIGH"},
					},
					types.MisconfResult{
						Namespace:      "testdata.kubernetes.id_200",
						Query:          "data.testdata.kubernetes.id_200.deny",
						Message:        "deny",
						PolicyMetadata: types.PolicyMetadata{ID: "ID-200", Type: "Kubernetes Security Check", Title: "Bad Deployment", Severity: "CRITICAL"},
					},
				}, Exceptions: types.MisconfResults(nil), Layer: types.Layer{Digest: "", DiffID: ""},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := scanner.New(tt.rootDir, tt.namespaces, tt.policyPaths, tt.dataPaths, false)
			require.NoError(t, err)

			got, err := s.ScanConfigs(context.Background(), tt.configs)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.Nil(t, got)
				return
			}
			require.NoError(t, err)

			require.Greater(t, len(got), 0)

			sort.Slice(got[0].Failures, func(i, j int) bool {
				if got[0].Failures[i].Namespace == got[0].Failures[j].Namespace {
					return got[0].Failures.Less(i, j)
				}
				return got[0].Failures[i].Namespace < got[0].Failures[j].Namespace
			})

			assert.Equal(t, tt.want, got[0])
		})
	}
}
