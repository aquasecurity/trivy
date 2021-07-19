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
							Type:               "Terraform Security Check powered by tfsec",
							ID:                 "AWS007",
							Description:        "Your port is egressing data to the internet",
							RecommendedActions: "Set a more restrictive cidr range",
							Severity:           "CRITICAL",
						},
					},
					{
						Message: `Resource 'variable.enableEncryption' passed check: Potentially sensitive data stored in "default" value of variable.`,
						PolicyMetadata: types.PolicyMetadata{
							Type:               "Terraform Security Check powered by tfsec",
							ID:                 "GEN001",
							Description:        "Default values could be exposing sensitive data",
							RecommendedActions: "Don't include sensitive data in variable defaults",
							Severity:           "CRITICAL",
						},
					},
					{
						Message: `Resource 'aws_security_group_rule.my-rule' passed check: Potentially sensitive data stored in block attribute.`,
						PolicyMetadata: types.PolicyMetadata{
							Type:               "Terraform Security Check powered by tfsec",
							ID:                 "GEN003",
							Description:        "Block attribute could be leaking secrets",
							RecommendedActions: "Don't include sensitive data in blocks",
							Severity:           "CRITICAL",
						},
					},
					{
						Message: `Resource 'azurerm_managed_disk.source' passed check: Potentially sensitive data stored in block attribute.`,
						PolicyMetadata: types.PolicyMetadata{
							Type:               "Terraform Security Check powered by tfsec",
							ID:                 "GEN003",
							Description:        "Block attribute could be leaking secrets",
							RecommendedActions: "Don't include sensitive data in blocks",
							Severity:           "CRITICAL",
						},
					},
					{
						Message: "Resource 'aws_security_group_rule.my-rule' passed check: The attribute has potentially sensitive data, passwords, tokens or keys in it",
						PolicyMetadata: types.PolicyMetadata{
							ID:                 "GEN005",
							Type:               "Terraform Security Check powered by tfsec",
							Description:        "Sensitive credentials may be compromised",
							Severity:           "CRITICAL",
							RecommendedActions: "Check the code for vulnerabilities and move to variables",
						},
					},
					{
						Message: "Resource 'azurerm_managed_disk.source' passed check: The attribute has potentially sensitive data, passwords, tokens or keys in it",
						PolicyMetadata: types.PolicyMetadata{
							ID:                 "GEN005",
							Type:               "Terraform Security Check powered by tfsec",
							Description:        "Sensitive credentials may be compromised",
							Severity:           "CRITICAL",
							RecommendedActions: "Check the code for vulnerabilities and move to variables",
						},
					},
					{
						Message: "Resource 'variable.enableEncryption' passed check: The attribute has potentially sensitive data, passwords, tokens or keys in it",
						PolicyMetadata: types.PolicyMetadata{
							ID:                 "GEN005",
							Type:               "Terraform Security Check powered by tfsec",
							Description:        "Sensitive credentials may be compromised",
							Severity:           "CRITICAL",
							RecommendedActions: "Check the code for vulnerabilities and move to variables",
						},
					},
				},
				Failures: []types.MisconfResult{
					{
						Message: "Resource 'aws_security_group_rule.my-rule' defines a fully open ingress security group rule.",
						PolicyMetadata: types.PolicyMetadata{
							ID:                 "AWS006",
							Type:               "Terraform Security Check powered by tfsec",
							Title:              "An ingress security group rule allows traffic from /0.",
							Description:        "Your port exposed to the internet",
							RecommendedActions: "Set a more restrictive cidr range",
							Severity:           "CRITICAL",
							References: []string{
								"https://tfsec.dev/docs/aws/AWS006/",
								"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules-reference.html",
							},
						},
					},
					{
						Message: "Resource 'aws_security_group_rule.my-rule' should include a description for auditing purposes.",
						PolicyMetadata: types.PolicyMetadata{
							ID:                 "AWS018",
							Type:               "Terraform Security Check powered by tfsec",
							Title:              "Missing description for security group/security group rule.",
							Description:        "Descriptions provide context for the firewall rule reasons",
							RecommendedActions: "Add descriptions for all security groups and rules",
							Severity:           "LOW",
							References: []string{
								"https://tfsec.dev/docs/aws/AWS018/",
								"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group",
								"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule",
								"https://www.cloudconformity.com/knowledge-base/aws/EC2/security-group-rules-description.html",
							},
						},
					},
					{
						Message: "Resource 'azurerm_managed_disk.source' defines an unencrypted managed disk.",
						PolicyMetadata: types.PolicyMetadata{
							ID:                 "AZU003",
							Type:               "Terraform Security Check powered by tfsec",
							Title:              "Unencrypted managed disk.",
							Description:        "Data could be read if compromised",
							RecommendedActions: "Enable encryption on managed disks",
							Severity:           "HIGH",
							References: []string{
								"https://tfsec.dev/docs/azure/AZU003/",
								"https://docs.microsoft.com/en-us/azure/virtual-machines/linux/disk-encryption",
								"https://www.terraform.io/docs/providers/azurerm/r/managed_disk.html",
							},
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

			sort.Slice(got[0].Failures, func(i, j int) bool {
				return got[0].Failures[i].Namespace < got[0].Failures[j].Namespace
			})

			assert.Equal(t, tt.want, got[0])
		})
	}
}
