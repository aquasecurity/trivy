package compute

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Compute struct {
	Firewalls          []Firewall
	LoadBalancers      []LoadBalancer
	Droplets           []Droplet
	KubernetesClusters []KubernetesCluster
}

type Firewall struct {
	Metadata      defsecTypes.Metadata
	OutboundRules []OutboundFirewallRule
	InboundRules  []InboundFirewallRule
}

type KubernetesCluster struct {
	Metadata     defsecTypes.Metadata
	SurgeUpgrade defsecTypes.BoolValue
	AutoUpgrade  defsecTypes.BoolValue
}

type LoadBalancer struct {
	Metadata            defsecTypes.Metadata
	ForwardingRules     []ForwardingRule
	RedirectHttpToHttps defsecTypes.BoolValue
}

type ForwardingRule struct {
	Metadata      defsecTypes.Metadata
	EntryProtocol defsecTypes.StringValue
}

type OutboundFirewallRule struct {
	Metadata             defsecTypes.Metadata
	DestinationAddresses []defsecTypes.StringValue
}

type InboundFirewallRule struct {
	Metadata        defsecTypes.Metadata
	SourceAddresses []defsecTypes.StringValue
}

type Droplet struct {
	Metadata defsecTypes.Metadata
	SSHKeys  []defsecTypes.StringValue
}
