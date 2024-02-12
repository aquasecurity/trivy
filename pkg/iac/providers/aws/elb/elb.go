package elb

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
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
	Metadata                defsecTypes.Metadata
	Type                    defsecTypes.StringValue
	DropInvalidHeaderFields defsecTypes.BoolValue
	Internal                defsecTypes.BoolValue
	Listeners               []Listener
}

type Listener struct {
	Metadata       defsecTypes.Metadata
	Protocol       defsecTypes.StringValue
	TLSPolicy      defsecTypes.StringValue
	DefaultActions []Action
}

type Action struct {
	Metadata defsecTypes.Metadata
	Type     defsecTypes.StringValue
}
