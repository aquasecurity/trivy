package network

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type LoadBalancer struct {
	Metadata  defsecTypes.MisconfigMetadata
	Listeners []LoadBalancerListener
}

type LoadBalancerListener struct {
	Metadata  defsecTypes.MisconfigMetadata
	Protocol  defsecTypes.StringValue
	TLSPolicy defsecTypes.StringValue
}
