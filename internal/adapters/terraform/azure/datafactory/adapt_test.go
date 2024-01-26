package datafactory

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/azure/datafactory"

	"github.com/aquasecurity/trivy/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/trivy/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_adaptFactory(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  datafactory.Factory
	}{
		{
			name: "defined",
			terraform: `
			resource "azurerm_data_factory" "example" {
				name                = "example"
				location            = azurerm_resource_group.example.location
				resource_group_name = azurerm_resource_group.example.name
				public_network_enabled = false
			  }
`,
			expected: datafactory.Factory{
				Metadata:            defsecTypes.NewTestMetadata(),
				EnablePublicNetwork: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
			},
		},
		{
			name: "default",
			terraform: `
			resource "azurerm_data_factory" "example" {
				name                = "example"
			  }
`,
			expected: datafactory.Factory{
				Metadata:            defsecTypes.NewTestMetadata(),
				EnablePublicNetwork: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptFactory(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "azurerm_data_factory" "example" {
		name                = "example"
		location            = azurerm_resource_group.example.location
		resource_group_name = azurerm_resource_group.example.name
		public_network_enabled = false
	  }`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.DataFactories, 1)
	dataFactory := adapted.DataFactories[0]

	assert.Equal(t, 6, dataFactory.EnablePublicNetwork.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 6, dataFactory.EnablePublicNetwork.GetMetadata().Range().GetEndLine())

}
