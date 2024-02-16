package eks

import (
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/eks"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_adaptCluster(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  eks.Cluster
	}{
		{
			name: "configured",
			terraform: `
			resource "aws_eks_cluster" "example" {
				encryption_config {
					resources = [ "secrets" ]
					provider {
						key_arn = "key-arn"
					}
				}
			
				enabled_cluster_log_types = ["api", "authenticator", "audit", "scheduler", "controllerManager"]
			
				name = "good_example_cluster"
				role_arn = var.cluster_arn
				vpc_config {
					endpoint_public_access = false
					public_access_cidrs = ["10.2.0.0/8"]
				}
			}
`,
			expected: eks.Cluster{
				Metadata: iacTypes.NewTestMetadata(),
				Logging: eks.Logging{
					Metadata:          iacTypes.NewTestMetadata(),
					API:               iacTypes.Bool(true, iacTypes.NewTestMetadata()),
					Authenticator:     iacTypes.Bool(true, iacTypes.NewTestMetadata()),
					Audit:             iacTypes.Bool(true, iacTypes.NewTestMetadata()),
					Scheduler:         iacTypes.Bool(true, iacTypes.NewTestMetadata()),
					ControllerManager: iacTypes.Bool(true, iacTypes.NewTestMetadata()),
				},
				Encryption: eks.Encryption{
					Metadata: iacTypes.NewTestMetadata(),
					Secrets:  iacTypes.Bool(true, iacTypes.NewTestMetadata()),
					KMSKeyID: iacTypes.String("key-arn", iacTypes.NewTestMetadata()),
				},
				PublicAccessEnabled: iacTypes.Bool(false, iacTypes.NewTestMetadata()),
				PublicAccessCIDRs: []iacTypes.StringValue{
					iacTypes.String("10.2.0.0/8", iacTypes.NewTestMetadata()),
				},
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "aws_eks_cluster" "example" {
			}
`,
			expected: eks.Cluster{
				Metadata: iacTypes.NewTestMetadata(),
				Logging: eks.Logging{
					Metadata:          iacTypes.NewTestMetadata(),
					API:               iacTypes.Bool(false, iacTypes.NewTestMetadata()),
					Authenticator:     iacTypes.Bool(false, iacTypes.NewTestMetadata()),
					Audit:             iacTypes.Bool(false, iacTypes.NewTestMetadata()),
					Scheduler:         iacTypes.Bool(false, iacTypes.NewTestMetadata()),
					ControllerManager: iacTypes.Bool(false, iacTypes.NewTestMetadata()),
				},
				Encryption: eks.Encryption{
					Metadata: iacTypes.NewTestMetadata(),
					Secrets:  iacTypes.Bool(false, iacTypes.NewTestMetadata()),
					KMSKeyID: iacTypes.String("", iacTypes.NewTestMetadata()),
				},
				PublicAccessEnabled: iacTypes.Bool(true, iacTypes.NewTestMetadata()),
				PublicAccessCIDRs:   nil,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptCluster(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_eks_cluster" "example" {
		encryption_config {
			resources = [ "secrets" ]
			provider {
				key_arn = "key-arn"
			}
		}
	
		enabled_cluster_log_types = ["api", "authenticator", "audit", "scheduler", "controllerManager"]
	
		name = "good_example_cluster"
		role_arn = var.cluster_arn
		vpc_config {
			endpoint_public_access = false
			public_access_cidrs = ["10.2.0.0/8"]
		}
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Clusters, 1)
	cluster := adapted.Clusters[0]

	assert.Equal(t, 2, cluster.Metadata.Range().GetStartLine())
	assert.Equal(t, 18, cluster.Metadata.Range().GetEndLine())

	assert.Equal(t, 3, cluster.Encryption.Metadata.Range().GetStartLine())
	assert.Equal(t, 8, cluster.Encryption.Metadata.Range().GetEndLine())

	assert.Equal(t, 4, cluster.Encryption.Secrets.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, cluster.Encryption.Secrets.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 6, cluster.Encryption.KMSKeyID.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 6, cluster.Encryption.KMSKeyID.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 10, cluster.Logging.Metadata.Range().GetStartLine())
	assert.Equal(t, 10, cluster.Logging.Metadata.Range().GetEndLine())

	assert.Equal(t, 10, cluster.Logging.API.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 10, cluster.Logging.API.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 10, cluster.Logging.Audit.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 10, cluster.Logging.Audit.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 10, cluster.Logging.Authenticator.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 10, cluster.Logging.Authenticator.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 10, cluster.Logging.Scheduler.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 10, cluster.Logging.Scheduler.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 10, cluster.Logging.ControllerManager.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 10, cluster.Logging.ControllerManager.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 15, cluster.PublicAccessEnabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 15, cluster.PublicAccessEnabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 16, cluster.PublicAccessCIDRs[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 16, cluster.PublicAccessCIDRs[0].GetMetadata().Range().GetEndLine())

}
