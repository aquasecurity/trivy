package datafactory

import (
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/datafactory"

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
				Metadata:            iacTypes.NewTestMetadata(),
				EnablePublicNetwork: iacTypes.Bool(false, iacTypes.NewTestMetadata()),
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
				Metadata:            iacTypes.NewTestMetadata(),
				EnablePublicNetwork: iacTypes.Bool(true, iacTypes.NewTestMetadata()),
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
