package nas

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
)

func TestLines(t *testing.T) {
	src := `
resource "nifcloud_nas_instance" "example" {
	network_id = "example-network"
}

resource "nifcloud_nas_security_group" "example" {
	description = "memo"

	rule {
	  cidr_ip = "0.0.0.0/0"
	}
}
`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.NASInstances, 1)
	require.Len(t, adapted.NASSecurityGroups, 1)

	nasInstance := adapted.NASInstances[0]
	nasSecurityGroup := adapted.NASSecurityGroups[0]

	assert.Equal(t, 3, nasInstance.NetworkID.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, nasInstance.NetworkID.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 7, nasSecurityGroup.Description.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 7, nasSecurityGroup.Description.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 10, nasSecurityGroup.CIDRs[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 10, nasSecurityGroup.CIDRs[0].GetMetadata().Range().GetEndLine())
}
