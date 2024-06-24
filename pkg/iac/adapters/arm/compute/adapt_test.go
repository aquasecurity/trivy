package compute

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	azure2 "github.com/aquasecurity/trivy/pkg/iac/scanners/azure"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func Test_AdaptLinuxVM(t *testing.T) {

	input := azure2.Deployment{
		Resources: []azure2.Resource{
			{
				Type: azure2.NewValue("Microsoft.Compute/virtualMachines", types.NewTestMetadata()),
				Properties: azure2.NewValue(map[string]azure2.Value{
					"osProfile": azure2.NewValue(map[string]azure2.Value{
						"linuxConfiguration": azure2.NewValue(map[string]azure2.Value{
							"disablePasswordAuthentication": azure2.NewValue(true, types.NewTestMetadata()),
						}, types.NewTestMetadata()),
					}, types.NewTestMetadata()),
				}, types.NewTestMetadata()),
			},
		},
	}

	output := Adapt(input)

	require.Len(t, output.LinuxVirtualMachines, 1)
	require.Empty(t, output.WindowsVirtualMachines)

	linuxVM := output.LinuxVirtualMachines[0]
	assert.True(t, linuxVM.OSProfileLinuxConfig.DisablePasswordAuthentication.IsTrue())

}

func Test_AdaptWindowsVM(t *testing.T) {

	input := azure2.Deployment{
		Resources: []azure2.Resource{
			{
				Type: azure2.NewValue("Microsoft.Compute/virtualMachines", types.NewTestMetadata()),
				Properties: azure2.NewValue(map[string]azure2.Value{
					"osProfile": azure2.NewValue(map[string]azure2.Value{
						"windowsConfiguration": azure2.NewValue(make(map[string]azure2.Value), types.NewTestMetadata()),
					}, types.NewTestMetadata()),
				}, types.NewTestMetadata()),
			},
		},
	}

	output := Adapt(input)

	require.Empty(t, output.LinuxVirtualMachines)
	require.Len(t, output.WindowsVirtualMachines, 1)
}
