package openstack

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
)

func Test_Networking(t *testing.T) {

	src := `
resource "openstack_networking_secgroup_v2" "secgroup_1" {
  name        = "secgroup_1"
  description = "My neutron security group"
}

resource "openstack_networking_secgroup_rule_v2" "secgroup_rule_1" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 22
  port_range_max    = 22
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = "${openstack_networking_secgroup_v2.secgroup_1.id}"
}
`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Networking.SecurityGroups, 1)
	group := adapted.Networking.SecurityGroups[0]

	assert.True(t, group.Name.EqualTo("secgroup_1"))
	assert.Equal(t, 3, group.Name.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, group.Name.GetMetadata().Range().GetEndLine())

	assert.True(t, group.Description.EqualTo("My neutron security group"))
	assert.Equal(t, 4, group.Description.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, group.Description.GetMetadata().Range().GetEndLine())

	require.Len(t, group.Rules, 1)
	rule := group.Rules[0]

	assert.True(t, rule.IsIngress.IsTrue())
	assert.Equal(t, 8, rule.IsIngress.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 8, rule.IsIngress.GetMetadata().Range().GetEndLine())

	assert.True(t, rule.EtherType.EqualTo(4))
	assert.Equal(t, 9, rule.EtherType.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 9, rule.EtherType.GetMetadata().Range().GetEndLine())

	assert.True(t, rule.Protocol.EqualTo("tcp"))
	assert.Equal(t, 10, rule.Protocol.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 10, rule.Protocol.GetMetadata().Range().GetEndLine())

	assert.True(t, rule.PortMin.EqualTo(22))
	assert.Equal(t, 11, rule.PortMin.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 11, rule.PortMin.GetMetadata().Range().GetEndLine())

	assert.True(t, rule.PortMax.EqualTo(22))
	assert.Equal(t, 12, rule.PortMax.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 12, rule.PortMax.GetMetadata().Range().GetEndLine())

	assert.True(t, rule.CIDR.EqualTo("0.0.0.0/0"))
	assert.Equal(t, 13, rule.CIDR.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 13, rule.CIDR.GetMetadata().Range().GetEndLine())

}
