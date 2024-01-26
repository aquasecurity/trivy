package kinesis

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/kinesis"

	"github.com/aquasecurity/trivy/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/trivy/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_adaptStream(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  kinesis.Stream
	}{
		{
			name: "configured",
			terraform: `
			resource "aws_kinesis_stream" "example" {
				encryption_type = "KMS"
				kms_key_id = "my/special/key"
			}
`,
			expected: kinesis.Stream{
				Metadata: defsecTypes.NewTestMetadata(),
				Encryption: kinesis.Encryption{
					Metadata: defsecTypes.NewTestMetadata(),
					Type:     defsecTypes.String("KMS", defsecTypes.NewTestMetadata()),
					KMSKeyID: defsecTypes.String("my/special/key", defsecTypes.NewTestMetadata()),
				},
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "aws_kinesis_stream" "example" {
			}
`,
			expected: kinesis.Stream{
				Metadata: defsecTypes.NewTestMetadata(),
				Encryption: kinesis.Encryption{
					Metadata: defsecTypes.NewTestMetadata(),
					Type:     defsecTypes.String("NONE", defsecTypes.NewTestMetadata()),
					KMSKeyID: defsecTypes.String("", defsecTypes.NewTestMetadata()),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptStream(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_kinesis_stream" "example" {
		encryption_type = "KMS"
		kms_key_id = "my/special/key"
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Streams, 1)
	stream := adapted.Streams[0]

	assert.Equal(t, 2, stream.Metadata.Range().GetStartLine())
	assert.Equal(t, 5, stream.Metadata.Range().GetEndLine())

	assert.Equal(t, 3, stream.Encryption.Type.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, stream.Encryption.Type.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 4, stream.Encryption.KMSKeyID.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, stream.Encryption.KMSKeyID.GetMetadata().Range().GetEndLine())
}
