package network

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type ElasticLoadBalancer struct {
	Metadata          defsecTypes.Metadata
	NetworkInterfaces []NetworkInterface
	Listeners         []ElasticLoadBalancerListener
}

type ElasticLoadBalancerListener struct {
	Metadata defsecTypes.Metadata
	Protocol defsecTypes.StringValue
}
