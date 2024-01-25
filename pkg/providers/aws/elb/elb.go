package elb

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type ELB struct {
	LoadBalancers []LoadBalancer
}

const (
	TypeApplication = "application"
	TypeGateway     = "gateway"
	TypeNetwork     = "network"
	TypeClassic     = "classic"
)

type LoadBalancer struct {
	Metadata                defsecTypes.MisconfigMetadata
	Type                    defsecTypes.StringValue
	DropInvalidHeaderFields defsecTypes.BoolValue
	Internal                defsecTypes.BoolValue
	Listeners               []Listener
}

type Listener struct {
	Metadata       defsecTypes.MisconfigMetadata
	Protocol       defsecTypes.StringValue
	TLSPolicy      defsecTypes.StringValue
	DefaultActions []Action
}

type Action struct {
	Metadata defsecTypes.MisconfigMetadata
	Type     defsecTypes.StringValue
}
