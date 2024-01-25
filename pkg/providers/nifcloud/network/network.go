package network

import defsecTypes "github.com/aquasecurity/trivy/pkg/types"

type Network struct {
	ElasticLoadBalancers []ElasticLoadBalancer
	LoadBalancers        []LoadBalancer
	Routers              []Router
	VpnGateways          []VpnGateway
}

type NetworkInterface struct {
	Metadata     defsecTypes.MisconfigMetadata
	NetworkID    defsecTypes.StringValue
	IsVipNetwork defsecTypes.BoolValue
}
