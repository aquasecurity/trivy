package compute

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/arm/adaptertest"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/compute"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func TestAdapt(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected compute.Compute
	}{
		{
			name: "empty",
			source: `{
  "resources": [
    {
      "type": "Microsoft.Compute/disks",
      "properties": {}
    },
    {
      "type": "Microsoft.Compute/virtualMachines",
      "properties": {
        "osProfile": {
          "linuxConfiguration": {},
          "windowsConfiguration": {}
        }
      }
    }
  ]
}`,
			expected: compute.Compute{
				ManagedDisks:           []compute.ManagedDisk{{}},
				LinuxVirtualMachines:   []compute.LinuxVirtualMachine{{}},
				WindowsVirtualMachines: []compute.WindowsVirtualMachine{{}},
			},
		},
		{
			name: "complete",
			source: `{
  "resources": [
    {
      "type": "Microsoft.Compute/disks",
      "properties": {
        "encryption": {}
      }
    },
    {
      "type": "Microsoft.Compute/virtualMachines",
      "properties": {
        "osProfile": {
          "customData": "Zm9v",
          "linuxConfiguration": {
            "disablePasswordAuthentication": true
          },
          "windowsConfiguration": {}
        }
      }
    }
  ]
}`,
			expected: compute.Compute{
				ManagedDisks: []compute.ManagedDisk{{
					Encryption: compute.Encryption{
						Enabled: types.BoolTest(true),
					},
				}},
				LinuxVirtualMachines: []compute.LinuxVirtualMachine{{
					VirtualMachine: compute.VirtualMachine{
						CustomData: types.StringTest("Zm9v"),
					},
					OSProfileLinuxConfig: compute.OSProfileLinuxConfig{
						DisablePasswordAuthentication: types.BoolTest(true),
					},
				}},
				WindowsVirtualMachines: []compute.WindowsVirtualMachine{{
					VirtualMachine: compute.VirtualMachine{
						CustomData: types.StringTest("Zm9v"),
					},
				}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adaptertest.AdaptAndCompare(t, tt.source, tt.expected, Adapt)
		})
	}

}
