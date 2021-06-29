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
			name:    "terraform",
			rootDir: "testdata",
			configs: []types.Config{
				{
					Type:     types.Terraform,
					FilePath: "testdata/main.tf",
				},
			},
			want: types.Misconfiguration{
				FileType: types.Terraform,
				FilePath: "main.tf",
				Successes: []types.MisconfResult{
					{
						Message: "Resource 'aws_security_group_rule.my-rule' passed check: An egress security group rule allows traffic to /0.",
						PolicyMetadata: types.PolicyMetadata{
							Type:     "Terraform Security Check powered by tfsec",
							ID:       "AWS007",
							Severity: "UNKNOWN",
						},
					},
					{
						Message: `Resource 'variable.enableEncryption' passed check: Potentially sensitive data stored in "default" value of variable.`,
						PolicyMetadata: types.PolicyMetadata{
							Type:     "Terraform Security Check powered by tfsec",
							ID:       "GEN001",
							Severity: "CRITICAL",
						},
					},
					{
						Message: `Resource 'aws_security_group_rule.my-rule' passed check: Potentially sensitive data stored in block attribute.`,
						PolicyMetadata: types.PolicyMetadata{
							Type:     "Terraform Security Check powered by tfsec",
							ID:       "GEN003",
							Severity: "CRITICAL",
						},
					},
					{
						Message: `Resource 'azurerm_managed_disk.source' passed check: Potentially sensitive data stored in block attribute.`,
						PolicyMetadata: types.PolicyMetadata{
							Type:     "Terraform Security Check powered by tfsec",
							ID:       "GEN003",
							Severity: "CRITICAL",
						},
					},
				},
				Failures: []types.MisconfResult{
					{
						Message: "Resource 'aws_security_group_rule.my-rule' defines a fully open ingress security group rule.",
						PolicyMetadata: types.PolicyMetadata{
							Type:     "Terraform Security Check powered by tfsec",
							Title:    "An ingress security group rule allows traffic from /0.",
							ID:       "AWS006",
							Severity: "MEDIUM",
						},
					},
					{
						Message: "Resource 'aws_security_group_rule.my-rule' should include a description for auditing purposes.",
						PolicyMetadata: types.PolicyMetadata{
							Type:     "Terraform Security Check powered by tfsec",
							Title:    "Missing description for security group/security group rule.",
							ID:       "AWS018",
							Severity: "HIGH",
						},
					},
					{
						Message: "Resource 'azurerm_managed_disk.source' defines an unencrypted managed disk.",
						PolicyMetadata: types.PolicyMetadata{
							Type:     "Terraform Security Check powered by tfsec",
							Title:    "Unencrypted managed disk.",
							ID:       "AZU003",
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
			s, err := scanner.New(tt.rootDir, tt.namespaces, tt.policyPaths, tt.dataPaths)
			require.NoError(t, err)

			got, err := s.ScanConfigs(context.Background(), tt.configs)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.Nil(t, got)
				return
			}
			require.NoError(t, err)

			sort.Slice(got[0].Failures, func(i, j int) bool {
				return got[0].Failures[i].Namespace < got[0].Failures[j].Namespace
			})

			assert.Equal(t, tt.want, got[0])
		})
	}
}
