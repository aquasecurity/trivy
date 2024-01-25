package compute

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type Compute struct {
	Firewalls          []Firewall
	LoadBalancers      []LoadBalancer
	Droplets           []Droplet
	KubernetesClusters []KubernetesCluster
}

type Firewall struct {
	Metadata      defsecTypes.MisconfigMetadata
	OutboundRules []OutboundFirewallRule
	InboundRules  []InboundFirewallRule
}

type KubernetesCluster struct {
	Metadata     defsecTypes.MisconfigMetadata
	SurgeUpgrade defsecTypes.BoolValue
	AutoUpgrade  defsecTypes.BoolValue
}

type LoadBalancer struct {
	Metadata            defsecTypes.MisconfigMetadata
	ForwardingRules     []ForwardingRule
	RedirectHttpToHttps defsecTypes.BoolValue
}

type ForwardingRule struct {
	Metadata      defsecTypes.MisconfigMetadata
	EntryProtocol defsecTypes.StringValue
}

type OutboundFirewallRule struct {
	Metadata             defsecTypes.MisconfigMetadata
	DestinationAddresses []defsecTypes.StringValue
}

type InboundFirewallRule struct {
	Metadata        defsecTypes.MisconfigMetadata
	SourceAddresses []defsecTypes.StringValue
}

type Droplet struct {
	Metadata defsecTypes.MisconfigMetadata
	SSHKeys  []defsecTypes.StringValue
}
