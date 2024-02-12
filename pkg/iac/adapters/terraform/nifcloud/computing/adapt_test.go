package computing

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLines(t *testing.T) {
	src := `
resource "nifcloud_instance" "example" {
	security_group  = nifcloud_security_group.example.group_name

	network_interface {
		network_id   = "net-COMMON_PRIVATE"
	}
}

resource "nifcloud_security_group" "example" {
	group_name = "example"
	description = "memo"
}

resource "nifcloud_security_group_rule" "example" {
	type                 = "IN"
	security_group_names = [nifcloud_security_group.example.group_name]
	from_port            = 22
	to_port              = 22
	protocol             = "TCP"
	description          = "memo"
	cidr_ip              = "1.2.3.4/32"
}
`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Instances, 1)
	require.Len(t, adapted.SecurityGroups, 1)

	instance := adapted.Instances[0]
	sg := adapted.SecurityGroups[0]

	assert.Equal(t, 3, instance.SecurityGroup.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, instance.SecurityGroup.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 6, instance.NetworkInterfaces[0].NetworkID.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 6, instance.NetworkInterfaces[0].NetworkID.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 12, sg.Description.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 12, sg.Description.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 21, sg.IngressRules[0].Description.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 21, sg.IngressRules[0].Description.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 22, sg.IngressRules[0].CIDR.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 22, sg.IngressRules[0].CIDR.GetMetadata().Range().GetEndLine())
}
