package network

import (
	"github.com/aquasecurity/trivy/internal/iac/providers/nifcloud/network"
	"github.com/aquasecurity/trivy/internal/iac/terraform"
)

func Adapt(modules terraform.Modules) network.Network {

	return network.Network{
		ElasticLoadBalancers: adaptElasticLoadBalancers(modules),
		LoadBalancers:        adaptLoadBalancers(modules),
		Routers:              adaptRouters(modules),
		VpnGateways:          adaptVpnGateways(modules),
	}
}
