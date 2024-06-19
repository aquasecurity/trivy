package monitor

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/monitor"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Test_adaptLogProfile(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  monitor.LogProfile
	}{
		{
			name: "defined",
			terraform: `
			resource "azurerm_monitor_log_profile" "example" {
				categories = [
					"Action",
					"Delete",
					"Write",
				]

				retention_policy {
				  enabled = true
				  days    = 365
				}

				locations = [
					"eastus",
					"eastus2",
					"southcentralus"
				]
			  }
`,
			expected: monitor.LogProfile{
				Metadata: iacTypes.NewTestMetadata(),
				Categories: []iacTypes.StringValue{
					iacTypes.String("Action", iacTypes.NewTestMetadata()),
					iacTypes.String("Delete", iacTypes.NewTestMetadata()),
					iacTypes.String("Write", iacTypes.NewTestMetadata()),
				},
				RetentionPolicy: monitor.RetentionPolicy{
					Metadata: iacTypes.NewTestMetadata(),
					Enabled:  iacTypes.Bool(true, iacTypes.NewTestMetadata()),
					Days:     iacTypes.Int(365, iacTypes.NewTestMetadata()),
				},
				Locations: []iacTypes.StringValue{
					iacTypes.String("eastus", iacTypes.NewTestMetadata()),
					iacTypes.String("eastus2", iacTypes.NewTestMetadata()),
					iacTypes.String("southcentralus", iacTypes.NewTestMetadata()),
				},
			},
		},
		{
			name: "default",
			terraform: `
			resource "azurerm_monitor_log_profile" "example" {
			  }
`,
			expected: monitor.LogProfile{
				Metadata: iacTypes.NewTestMetadata(),
				RetentionPolicy: monitor.RetentionPolicy{
					Metadata: iacTypes.NewTestMetadata(),
					Enabled:  iacTypes.Bool(false, iacTypes.NewTestMetadata()),
					Days:     iacTypes.Int(0, iacTypes.NewTestMetadata()),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptLogProfile(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "azurerm_monitor_log_profile" "example" {
		categories = [
			"Action",
			"Delete",
			"Write",
		]

		retention_policy {
		  enabled = true
		  days    = 365
		}

		locations = [
			"eastus",
			"eastus2",
			"southcentralus"
		]
	  }`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.LogProfiles, 1)
	logProfile := adapted.LogProfiles[0]

	assert.Equal(t, 3, logProfile.Categories[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 7, logProfile.Categories[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 10, logProfile.RetentionPolicy.Enabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 10, logProfile.RetentionPolicy.Enabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 11, logProfile.RetentionPolicy.Days.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 11, logProfile.RetentionPolicy.Days.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 14, logProfile.Locations[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 18, logProfile.Locations[0].GetMetadata().Range().GetEndLine())
}
