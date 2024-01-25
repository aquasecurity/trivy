package monitor

import (
	"testing"

	defsecTypes "github.com/aquasecurity/trivy/pkg/types"

	"github.com/aquasecurity/trivy/pkg/providers/azure/monitor"

	"github.com/aquasecurity/trivy/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/trivy/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
				Metadata: defsecTypes.NewTestMisconfigMetadata(),
				Categories: []defsecTypes.StringValue{
					defsecTypes.String("Action", defsecTypes.NewTestMisconfigMetadata()),
					defsecTypes.String("Delete", defsecTypes.NewTestMisconfigMetadata()),
					defsecTypes.String("Write", defsecTypes.NewTestMisconfigMetadata()),
				},
				RetentionPolicy: monitor.RetentionPolicy{
					Metadata: defsecTypes.NewTestMisconfigMetadata(),
					Enabled:  defsecTypes.Bool(true, defsecTypes.NewTestMisconfigMetadata()),
					Days:     defsecTypes.Int(365, defsecTypes.NewTestMisconfigMetadata()),
				},
				Locations: []defsecTypes.StringValue{
					defsecTypes.String("eastus", defsecTypes.NewTestMisconfigMetadata()),
					defsecTypes.String("eastus2", defsecTypes.NewTestMisconfigMetadata()),
					defsecTypes.String("southcentralus", defsecTypes.NewTestMisconfigMetadata()),
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
				Metadata: defsecTypes.NewTestMisconfigMetadata(),
				RetentionPolicy: monitor.RetentionPolicy{
					Metadata: defsecTypes.NewTestMisconfigMetadata(),
					Enabled:  defsecTypes.Bool(false, defsecTypes.NewTestMisconfigMetadata()),
					Days:     defsecTypes.Int(0, defsecTypes.NewTestMisconfigMetadata()),
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
