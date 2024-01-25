package network

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type ElasticLoadBalancer struct {
	Metadata          defsecTypes.MisconfigMetadata
	NetworkInterfaces []NetworkInterface
	Listeners         []ElasticLoadBalancerListener
}

type ElasticLoadBalancerListener struct {
	Metadata defsecTypes.MisconfigMetadata
	Protocol defsecTypes.StringValue
}
