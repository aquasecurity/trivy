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
			name:    "cloudformation",
			rootDir: "testdata",
			configs: []types.Config{
				{
					Type:     types.CloudFormation,
					FilePath: "testdata/cloudformation.yaml",
				},
			},
			namespaces: nil,
			want: types.Misconfiguration{
				FileType: types.CloudFormation,
				FilePath: "cloudformation.yaml",
				Successes: []types.MisconfResult{
					{
						Message: "Resource 'S3Bucket' passed check: S3 Access Block should Ignore Public Acl",
						PolicyMetadata: types.PolicyMetadata{
							Type:               "Cloudformation Security Check powered by cfsec",
							ID:                 "AVD-AWS-0091",
							Title:              "S3 Access Block should Ignore Public Acl",
							Description:        "PUT calls with public ACLs specified can make objects public",
							RecommendedActions: "Enable ignoring the application of public ACLs in PUT calls",
							Severity:           "HIGH",
							References:         []string{"https://cfsec.dev/docs/s3/ignore-public-acls/#s3", "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"},
						},
						IacMetadata: types.IacMetadata{
							Resource:  "S3Bucket",
							StartLine: 12,
							EndLine:   24,
						},
					},
					{
						Message: "Resource 'S3Bucket' passed check: S3 Bucket does not have logging enabled.",
						PolicyMetadata: types.PolicyMetadata{
							ID:                 "AVD-AWS-0092",
							Type:               "Cloudformation Security Check powered by cfsec",
							Title:              "S3 Bucket does not have logging enabled.",
							Description:        "There is no way to determine the access to this bucket",
							Severity:           "HIGH",
							RecommendedActions: "Add a logging block to the resource to enable access logging",
							References:         []string{"https://cfsec.dev/docs/s3/no-public-access-with-acl/#s3", "https://docs.aws.amazon.com/AmazonS3/latest/dev/ServerLogs.html"},
						}, IacMetadata: types.IacMetadata{
							Resource:  "S3Bucket",
							StartLine: 12,
							EndLine:   24,
						},
					},
					{
						Message: "Resource 'S3Bucket' passed check: S3 buckets should each define an aws_s3_bucket_public_access_block",
						PolicyMetadata: types.PolicyMetadata{
							ID:                 "AVD-AWS-0094",
							Type:               "Cloudformation Security Check powered by cfsec",
							Title:              "S3 buckets should each define an aws_s3_bucket_public_access_block",
							Description:        "Public access policies may be applied to sensitive data buckets",
							Severity:           "LOW",
							RecommendedActions: "Define a aws_s3_bucket_public_access_block for the given bucket to control public access policies",
							References:         []string{"https://cfsec.dev/docs/s3/specify-public-access-block/#s3", "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"},
						},
						IacMetadata: types.IacMetadata{
							Resource:  "S3Bucket",
							StartLine: 12,
							EndLine:   24,
						},
					},
				},
				Failures: []types.MisconfResult{
					{
						Message: "Public access block does not block public ACLs",
						PolicyMetadata: types.PolicyMetadata{
							ID:                 "AVD-AWS-0086",
							Type:               "Cloudformation Security Check powered by cfsec",
							Title:              "S3 Access block should block public ACL",
							Description:        "PUT calls with public ACLs specified can make objects public",
							Severity:           "HIGH",
							RecommendedActions: "Enable blocking any PUT calls with a public ACL specified",
							References:         []string{"https://cfsec.dev/docs/s3/block-public-acls/#s3", "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"},
						},
						IacMetadata: types.IacMetadata{
							Resource:  "S3Bucket",
							StartLine: 12,
							EndLine:   24,
						},
					},
					{
						Message: "Public access block does not block public policies",
						PolicyMetadata: types.PolicyMetadata{
							ID:                 "AVD-AWS-0087",
							Type:               "Cloudformation Security Check powered by cfsec",
							Title:              "S3 Access block should block public policy",
							Description:        "Users could put a policy that allows public access",
							Severity:           "HIGH",
							RecommendedActions: "Prevent policies that allow public access being PUT",
							References:         []string{"https://cfsec.dev/docs/s3/block-public-policy/#s3", "https://docs.aws.amazon.com/AmazonS3/latest/dev-retired/access-control-block-public-access.html"},
						},
						IacMetadata: types.IacMetadata{
							Resource:  "S3Bucket",
							StartLine: 12,
							EndLine:   24,
						},
					},
					{
						Message: "Bucket does not have encryption enabled",
						PolicyMetadata: types.PolicyMetadata{
							ID:                 "AVD-AWS-0088",
							Type:               "Cloudformation Security Check powered by cfsec",
							Title:              "Unencrypted S3 bucket.",
							Description:        "The bucket objects could be read if compromised",
							Severity:           "HIGH",
							RecommendedActions: "Configure bucket encryption",
							References:         []string{"https://cfsec.dev/docs/s3/enable-bucket-encryption/#s3", "https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html"},
						},
						IacMetadata: types.IacMetadata{
							Resource:  "S3Bucket",
							StartLine: 12,
							EndLine:   24,
						},
					},
					{
						Message: "Bucket does not have logging enabled",
						PolicyMetadata: types.PolicyMetadata{
							ID:                 "AVD-AWS-0089",
							Type:               "Cloudformation Security Check powered by cfsec",
							Title:              "S3 Bucket does not have logging enabled.",
							Description:        "There is no way to determine the access to this bucket",
							Severity:           "MEDIUM",
							RecommendedActions: "Add a logging block to the resource to enable access logging",
							References:         []string{"https://cfsec.dev/docs/s3/enable-bucket-logging/#s3", "https://docs.aws.amazon.com/AmazonS3/latest/dev/ServerLogs.html"},
						},
						IacMetadata: types.IacMetadata{
							Resource:  "S3Bucket",
							StartLine: 12,
							EndLine:   24,
						},
					},
					{
						Message: "Bucket does not have versioning enabled",
						PolicyMetadata: types.PolicyMetadata{
							ID:                 "AVD-AWS-0090",
							Type:               "Cloudformation Security Check powered by cfsec",
							Title:              "S3 Data should be versioned",
							Description:        "Deleted or modified data would not be recoverable",
							Severity:           "MEDIUM",
							RecommendedActions: "Enable versioning to protect against accidental/malicious removal or modification",
							References:         []string{"https://cfsec.dev/docs/s3/enable-versioning/#s3", "https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html"},
						},
						IacMetadata: types.IacMetadata{
							Resource:  "S3Bucket",
							StartLine: 12,
							EndLine:   24,
						},
					},
					{
						Message: "Public access block does not restrict public buckets",
						PolicyMetadata: types.PolicyMetadata{
							ID:                 "AVD-AWS-0093",
							Type:               "Cloudformation Security Check powered by cfsec",
							Title:              "S3 Access block should restrict public bucket to limit access",
							Description:        "Public buckets can be accessed by anyone",
							Severity:           "HIGH",
							RecommendedActions: "Limit the access to public buckets to only the owner or AWS Services (eg; CloudFront)",
							References:         []string{"https://cfsec.dev/docs/s3/no-public-buckets/#s3", "https://docs.aws.amazon.com/AmazonS3/latest/dev-retired/access-control-block-public-access.html"},
						},
						IacMetadata: types.IacMetadata{
							Resource:  "S3Bucket",
							StartLine: 12,
							EndLine:   24,
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
						IacMetadata: types.IacMetadata{
							Resource:  "aws_security_group_rule.my-rule",
							StartLine: 1,
							EndLine:   4,
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
						IacMetadata: types.IacMetadata{
							Resource:  "aws_security_group_rule.my-rule",
							StartLine: 1,
							EndLine:   4,
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
						IacMetadata: types.IacMetadata{
							Resource:  "aws_security_group_rule.my-rule",
							StartLine: 1,
							EndLine:   4,
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
						IacMetadata: types.IacMetadata{
							Resource:  "azurerm_managed_disk.source",
							StartLine: 10,
							EndLine:   14,
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
						IacMetadata: types.IacMetadata{
							Resource:  "aws_security_group_rule.my-rule",
							StartLine: 1,
							EndLine:   4,
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
						IacMetadata: types.IacMetadata{
							Resource:  "azurerm_managed_disk.source",
							StartLine: 10,
							EndLine:   14,
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
						IacMetadata: types.IacMetadata{
							Resource:  "variable.enableEncryption",
							StartLine: 6,
							EndLine:   8,
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
						IacMetadata: types.IacMetadata{
							Resource:  "variable.enableEncryption",
							StartLine: 6,
							EndLine:   8,
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
						IacMetadata: types.IacMetadata{
							Resource:  "aws_security_group_rule.my-rule",
							StartLine: 1,
							EndLine:   4,
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
						IacMetadata: types.IacMetadata{
							Resource:  "aws_security_group_rule.my-rule",
							StartLine: 3,
							EndLine:   3,
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
						IacMetadata: types.IacMetadata{
							Resource:  "azurerm_managed_disk.source",
							StartLine: 12,
							EndLine:   12,
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
