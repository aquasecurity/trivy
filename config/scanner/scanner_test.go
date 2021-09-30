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
						Message: "Resource 'aws_security_group_rule.my-rule' passed check: Ensures that usage of security groups with inline rules and security group rule resources are not mixed.",
						PolicyMetadata: types.PolicyMetadata{
							Type:               "Terraform Security Check powered by tfsec",
							ID:                 "AVD-AWS-0100",
							Description:        "Security group rules will be overwritten and will result in unintended blocking of network traffic",
							RecommendedActions: "Either define all of a security group's rules inline, or none of the security group's rules inline",
							Severity:           "LOW",
						},
					},
					{
						Message: `Resource 'aws_security_group_rule.my-rule' passed check: An egress security group rule allows traffic to /0.`,
						PolicyMetadata: types.PolicyMetadata{
							Type:               "Terraform Security Check powered by tfsec",
							ID:                 "AVD-AWS-0104",
							Description:        "Your port is egressing data to the internet",
							RecommendedActions: "Set a more restrictive cidr range",
							Severity:           "CRITICAL",
						},
					},
					{
						Message: "Resource 'aws_security_group_rule.my-rule' passed check: Potentially sensitive data stored in block attribute.",
						PolicyMetadata: types.PolicyMetadata{
							ID:                 "AVD-GEN-0001",
							Type:               "Terraform Security Check powered by tfsec",
							Description:        "Block attribute could be leaking secrets",
							Severity:           "CRITICAL",
							RecommendedActions: "Don't include sensitive data in blocks",
						},
					},
					{
						Message: `Resource 'azurerm_managed_disk.source' passed check: Potentially sensitive data stored in block attribute.`,
						PolicyMetadata: types.PolicyMetadata{
							Type:               "Terraform Security Check powered by tfsec",
							ID:                 "AVD-GEN-0001",
							Description:        "Block attribute could be leaking secrets",
							RecommendedActions: "Don't include sensitive data in blocks",
							Severity:           "CRITICAL",
						},
					},
					{
						Message: "Resource 'aws_security_group_rule.my-rule' passed check: The attribute has potentially sensitive data, passwords, tokens or keys in it",
						PolicyMetadata: types.PolicyMetadata{
							ID:                 "AVD-GEN-0002",
							Type:               "Terraform Security Check powered by tfsec",
							Description:        "Sensitive credentials may be compromised",
							Severity:           "CRITICAL",
							RecommendedActions: "Check the code for vulnerabilities and move to variables",
						},
					},
					{
						Message: "Resource 'azurerm_managed_disk.source' passed check: The attribute has potentially sensitive data, passwords, tokens or keys in it",
						PolicyMetadata: types.PolicyMetadata{
							ID:                 "AVD-GEN-0002",
							Type:               "Terraform Security Check powered by tfsec",
							Description:        "Sensitive credentials may be compromised",
							Severity:           "CRITICAL",
							RecommendedActions: "Check the code for vulnerabilities and move to variables",
						},
					},

					{
						Message: "Resource 'variable.enableEncryption' passed check: The attribute has potentially sensitive data, passwords, tokens or keys in it",
						PolicyMetadata: types.PolicyMetadata{
							ID:                 "AVD-GEN-0002",
							Type:               "Terraform Security Check powered by tfsec",
							Description:        "Sensitive credentials may be compromised",
							Severity:           "CRITICAL",
							RecommendedActions: "Check the code for vulnerabilities and move to variables",
						},
					},
					{
						Message: `Resource 'variable.enableEncryption' passed check: Potentially sensitive data stored in "default" value of variable.`,
						PolicyMetadata: types.PolicyMetadata{
							Type:               "Terraform Security Check powered by tfsec",
							ID:                 "AVD-GEN-0004",
							Description:        "Default values could be exposing sensitive data",
							RecommendedActions: "Don't include sensitive data in variable defaults",
							Severity:           "CRITICAL",
						},
					},
				},
				Failures: []types.MisconfResult{
					{
						Message: "Resource 'aws_security_group_rule.my-rule' should include a description for auditing purposes.",
						PolicyMetadata: types.PolicyMetadata{
							ID:                 "AVD-AWS-0099",
							Type:               "Terraform Security Check powered by tfsec",
							Title:              "Missing description for security group/security group rule.",
							Description:        "Descriptions provide context for the firewall rule reasons",
							RecommendedActions: "Add descriptions for all security groups and rules",
							Severity:           "LOW",
							References: []string{
								"https://tfsec.dev/docs/aws/vpc/add-description-to-security-group#aws/vpc",
								"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group",
								"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule",
								"https://www.cloudconformity.com/knowledge-base/aws/EC2/security-group-rules-description.html",
							},
						},
					},
					{
						Message: "Resource 'aws_security_group_rule.my-rule' defines a fully open ingress security group rule.",
						PolicyMetadata: types.PolicyMetadata{
							ID:                 "AVD-AWS-0107",
							Type:               "Terraform Security Check powered by tfsec",
							Title:              "An ingress security group rule allows traffic from /0.",
							Description:        "Your port exposed to the internet",
							RecommendedActions: "Set a more restrictive cidr range",
							Severity:           "CRITICAL",
							References: []string{
								"https://tfsec.dev/docs/aws/vpc/no-public-ingress-sgr#aws/vpc",
								"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule#cidr_blocks",
								"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules-reference.html",
							},
						},
					},
					{
						Message: "Resource 'azurerm_managed_disk.source' defines an unencrypted managed disk.",
						PolicyMetadata: types.PolicyMetadata{
							ID:                 "AVD-AZU-0009",
							Type:               "Terraform Security Check powered by tfsec",
							Title:              "Enable disk encryption on managed disk",
							Description:        "Data could be read if compromised",
							RecommendedActions: "Enable encryption on managed disks",
							Severity:           "HIGH",
							References: []string{
								"https://tfsec.dev/docs/azure/compute/enable-disk-encryption#azure/compute",
								"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/managed_disk",
								"https://docs.microsoft.com/en-us/azure/virtual-machines/linux/disk-encryption",
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
				if got[0].Failures[i].Namespace == got[0].Failures[j].Namespace {
					return got[0].Failures.Less(i, j)
				}
				return got[0].Failures[i].Namespace < got[0].Failures[j].Namespace
			})

			assert.Equal(t, tt.want, got[0])
		})
	}
}
