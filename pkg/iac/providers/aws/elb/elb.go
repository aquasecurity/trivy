package elb

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
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

// DefaultTLSPolicy is the security policy that AWS assigns to an HTTPS or TLS listener
// created without one by any method other than the console (API, CLI, CloudFormation, Terraform).
// See https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html
const DefaultTLSPolicy = "ELBSecurityPolicy-2016-08"

type LoadBalancer struct {
	Metadata                iacTypes.Metadata
	Type                    iacTypes.StringValue
	DropInvalidHeaderFields iacTypes.BoolValue
	Internal                iacTypes.BoolValue
	Listeners               []Listener
}

type Listener struct {
	Metadata       iacTypes.Metadata
	Protocol       iacTypes.StringValue
	TLSPolicy      iacTypes.StringValue
	DefaultActions []Action
}

type Action struct {
	Metadata iacTypes.Metadata
	Type     iacTypes.StringValue
}
