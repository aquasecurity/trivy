package eks

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/eks"

	"github.com/aquasecurity/trivy/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/trivy/test/testutil"
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
				Metadata: defsecTypes.NewTestMetadata(),
				Logging: eks.Logging{
					Metadata:          defsecTypes.NewTestMetadata(),
					API:               defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
					Authenticator:     defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
					Audit:             defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
					Scheduler:         defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
					ControllerManager: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
				},
				Encryption: eks.Encryption{
					Metadata: defsecTypes.NewTestMetadata(),
					Secrets:  defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
					KMSKeyID: defsecTypes.String("key-arn", defsecTypes.NewTestMetadata()),
				},
				PublicAccessEnabled: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
				PublicAccessCIDRs: []defsecTypes.StringValue{
					defsecTypes.String("10.2.0.0/8", defsecTypes.NewTestMetadata()),
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
				Metadata: defsecTypes.NewTestMetadata(),
				Logging: eks.Logging{
					Metadata:          defsecTypes.NewTestMetadata(),
					API:               defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
					Authenticator:     defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
					Audit:             defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
					Scheduler:         defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
					ControllerManager: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
				},
				Encryption: eks.Encryption{
					Metadata: defsecTypes.NewTestMetadata(),
					Secrets:  defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
					KMSKeyID: defsecTypes.String("", defsecTypes.NewTestMetadata()),
				},
				PublicAccessEnabled: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
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
