package inventory_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/inventory"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/vars"
)

func TestInventory_ResolveVars(t *testing.T) {
	src := `
all:
  vars:
    location: dc1
    os: linux

leafs0:
  vars:
    os: nxos
  hosts:
    leaf01:
      ansible_host: 192.0.2.100
      role: custom-leaf

leafs1:
  vars:
    os: eos
    role: leaf
  hosts:
    leaf01:
      role: custom-leaf2
      tag: leafs1
    leaf02:
      ansible_host: 192.0.2.110

spines:
  vars:
    role: spine
  hosts:
    spine01:
      ansible_host: 192.0.2.120
    spine02:
      ansible_host: 192.0.2.130
      os: nxos

network0:
  vars:
    environment: dev
  children:
    leafs0:
    leafs1:
    spines:

network1:
  vars:
    environment: prod
  children:
    network0:
    leafs1:
    spines:

webservers:
  vars:
    role: web
  hosts:
    webserver01:
      ansible_host: 192.0.2.140
    webserver02:
      ansible_host: 192.0.2.150

datacenter:
  children:
    network0:
    network1:
    webservers:
`

	inv, err := inventory.ParseYAML([]byte(src))
	require.NoError(t, err)

	tests := []struct {
		hostName string
		expected vars.Vars
	}{
		{
			hostName: "leaf01",
			expected: vars.Vars{
				"location":     "dc1",          // from all
				"tag":          "leafs1",       // from leafs1
				"os":           "eos",          // from leafs1
				"role":         "custom-leaf2", // overridden at host
				"environment":  "dev",          // from network1
				"ansible_host": "192.0.2.100",  // from host
			},
		},
		{
			hostName: "leaf02",
			expected: vars.Vars{
				"location":     "dc1",
				"os":           "eos",  // from leafs1
				"role":         "leaf", // from leafs1
				"environment":  "dev",  // from network1
				"ansible_host": "192.0.2.110",
			},
		},
		{
			hostName: "spine01",
			expected: vars.Vars{
				"location":     "dc1",
				"os":           "linux", // from all
				"role":         "spine", // from spines
				"environment":  "dev",
				"ansible_host": "192.0.2.120",
			},
		},
		{
			hostName: "spine02",
			expected: vars.Vars{
				"location":     "dc1",
				"os":           "nxos", // overridden at host
				"role":         "spine",
				"environment":  "dev",
				"ansible_host": "192.0.2.130",
			},
		},
		{
			hostName: "webserver01",
			expected: vars.Vars{
				"location":     "dc1",
				"os":           "linux",
				"role":         "web",
				"ansible_host": "192.0.2.140",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.hostName, func(t *testing.T) {
			got := inv.ResolveVars(tt.hostName)
			require.Equal(t, tt.expected, got)
		})
	}
}
