package mq

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/mq"

	"github.com/aquasecurity/trivy/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/trivy/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_adaptBroker(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  mq.Broker
	}{
		{
			name: "audit logs",
			terraform: `
			resource "aws_mq_broker" "example" {
				logs {
				  audit = true
				}

				publicly_accessible = false
			  }
`,
			expected: mq.Broker{
				Metadata:     defsecTypes.NewTestMetadata(),
				PublicAccess: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
				Logging: mq.Logging{
					Metadata: defsecTypes.NewTestMetadata(),
					General:  defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
					Audit:    defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
				},
			},
		},
		{
			name: "general logs",
			terraform: `
			resource "aws_mq_broker" "example" {
				logs {
				  general = true
				}

				publicly_accessible = true
			  }
`,
			expected: mq.Broker{
				Metadata:     defsecTypes.NewTestMetadata(),
				PublicAccess: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
				Logging: mq.Logging{
					Metadata: defsecTypes.NewTestMetadata(),
					General:  defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
					Audit:    defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
				},
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "aws_mq_broker" "example" {
			  }
`,
			expected: mq.Broker{
				Metadata:     defsecTypes.NewTestMetadata(),
				PublicAccess: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
				Logging: mq.Logging{
					Metadata: defsecTypes.NewTestMetadata(),
					General:  defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
					Audit:    defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptBroker(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_mq_broker" "example" {
		logs {
		  general = true
		}

		publicly_accessible = true
	  }`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Brokers, 1)
	broker := adapted.Brokers[0]

	assert.Equal(t, 2, broker.Metadata.Range().GetStartLine())
	assert.Equal(t, 8, broker.Metadata.Range().GetEndLine())

	assert.Equal(t, 3, broker.Logging.Metadata.Range().GetStartLine())
	assert.Equal(t, 5, broker.Logging.Metadata.Range().GetEndLine())

	assert.Equal(t, 4, broker.Logging.General.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, broker.Logging.General.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 7, broker.PublicAccess.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 7, broker.PublicAccess.GetMetadata().Range().GetEndLine())
}
