package network

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
)

func TestLines(t *testing.T) {
	src := `
resource "nifcloud_elb" "example" {
    protocol = "HTTP"

	network_interface {
		network_id     = "net-COMMON_PRIVATE"
		is_vip_network = false
	}
}

resource "nifcloud_load_balancer" "example" {
	ssl_policy_id      = "example-ssl-policy-id"
	load_balancer_port = 8080
}

resource "nifcloud_router" "example" {
	security_group  = nifcloud_security_group.example.group_name

	network_interface {
		network_id   = "net-COMMON_PRIVATE"
	}
}

resource "nifcloud_security_group" "example" {
	group_name = "example"
	description = "memo"
}

resource "nifcloud_vpn_gateway" "example" {
	security_group  = nifcloud_security_group.example.group_name
}
`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.ElasticLoadBalancers, 1)
	require.Len(t, adapted.LoadBalancers, 1)
	require.Len(t, adapted.Routers, 1)
	require.Len(t, adapted.VpnGateways, 1)

	elb := adapted.ElasticLoadBalancers[0]
	lb := adapted.LoadBalancers[0]
	router := adapted.Routers[0]
	vpngw := adapted.VpnGateways[0]

	assert.Equal(t, 3, elb.Listeners[0].Protocol.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, elb.Listeners[0].Protocol.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 6, elb.NetworkInterfaces[0].NetworkID.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 6, elb.NetworkInterfaces[0].NetworkID.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 7, elb.NetworkInterfaces[0].IsVipNetwork.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 7, elb.NetworkInterfaces[0].IsVipNetwork.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 12, lb.Listeners[0].TLSPolicy.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 12, lb.Listeners[0].TLSPolicy.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 13, lb.Listeners[0].Protocol.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 13, lb.Listeners[0].Protocol.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 17, router.SecurityGroup.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 17, router.SecurityGroup.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 20, router.NetworkInterfaces[0].NetworkID.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 20, router.NetworkInterfaces[0].NetworkID.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 30, vpngw.SecurityGroup.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 30, vpngw.SecurityGroup.GetMetadata().Range().GetEndLine())

}
