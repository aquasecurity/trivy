package compute

import (
	"testing"

	"github.com/aquasecurity/defsec/pkg/types"
	"github.com/aquasecurity/trivy/pkg/scanners/azure"

	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/require"
)

func Test_AdaptLinuxVM(t *testing.T) {

	input := azure.Deployment{
		Resources: []azure.Resource{
			{
				Type: azure.NewValue("Microsoft.Compute/virtualMachines", types.NewTestMetadata()),
				Properties: azure.NewValue(map[string]azure.Value{
					"osProfile": azure.NewValue(map[string]azure.Value{
						"linuxConfiguration": azure.NewValue(map[string]azure.Value{
							"disablePasswordAuthentication": azure.NewValue(true, types.NewTestMetadata()),
						}, types.NewTestMetadata()),
					}, types.NewTestMetadata()),
				}, types.NewTestMetadata()),
			},
		},
	}

	output := Adapt(input)

	require.Len(t, output.LinuxVirtualMachines, 1)
	require.Len(t, output.WindowsVirtualMachines, 0)

	linuxVM := output.LinuxVirtualMachines[0]
	assert.True(t, linuxVM.OSProfileLinuxConfig.DisablePasswordAuthentication.IsTrue())

}

func Test_AdaptWindowsVM(t *testing.T) {

	input := azure.Deployment{
		Resources: []azure.Resource{
			{
				Type: azure.NewValue("Microsoft.Compute/virtualMachines", types.NewTestMetadata()),
				Properties: azure.NewValue(map[string]azure.Value{
					"osProfile": azure.NewValue(map[string]azure.Value{
						"windowsConfiguration": azure.NewValue(map[string]azure.Value{}, types.NewTestMetadata()),
					}, types.NewTestMetadata()),
				}, types.NewTestMetadata()),
			},
		},
	}

	output := Adapt(input)

	require.Len(t, output.LinuxVirtualMachines, 0)
	require.Len(t, output.WindowsVirtualMachines, 1)
}
