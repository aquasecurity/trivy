package sns

import (
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/sns"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_adaptTopic(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  sns.Topic
	}{
		{
			name: "defined",
			terraform: `
			resource "aws_sns_topic" "good_example" {
				kms_master_key_id = "/blah"
			}
`,
			expected: sns.Topic{
				Metadata: iacTypes.NewTestMetadata(),
				ARN:      iacTypes.String("", iacTypes.NewTestMetadata()),
				Encryption: sns.Encryption{
					Metadata: iacTypes.NewTestMetadata(),
					KMSKeyID: iacTypes.String("/blah", iacTypes.NewTestMetadata()),
				},
			},
		},
		{
			name: "default",
			terraform: `
			resource "aws_sns_topic" "good_example" {
			}
`,
			expected: sns.Topic{
				Metadata: iacTypes.NewTestMetadata(),
				ARN:      iacTypes.String("", iacTypes.NewTestMetadata()),
				Encryption: sns.Encryption{
					Metadata: iacTypes.NewTestMetadata(),
					KMSKeyID: iacTypes.String("", iacTypes.NewTestMetadata()),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptTopic(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_sns_topic" "good_example" {
		kms_master_key_id = "/blah"
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Topics, 1)
	topic := adapted.Topics[0]

	assert.Equal(t, 2, topic.Metadata.Range().GetStartLine())
	assert.Equal(t, 4, topic.Metadata.Range().GetEndLine())

	assert.Equal(t, 3, topic.Encryption.KMSKeyID.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, topic.Encryption.KMSKeyID.GetMetadata().Range().GetEndLine())
}
