package compute

import (
	"strconv"
	"strings"

	"github.com/aquasecurity/defsec/parsers/types"

	"github.com/aquasecurity/defsec/parsers/terraform"
	"github.com/aquasecurity/defsec/providers/google/compute"
)

func adaptNetworks(modules terraform.Modules) (networks []compute.Network) {

	networkMap := make(map[string]compute.Network)

	for _, networkBlock := range modules.GetResourcesByType("google_compute_network") {
		network := compute.Network{
			Metadata:    networkBlock.GetMetadata(),
			Firewall:    nil,
			Subnetworks: nil,
		}
		networkMap[networkBlock.ID()] = network
	}

	for _, subnetworkBlock := range modules.GetResourcesByType("google_compute_subnetwork") {

		subnetwork := compute.SubNetwork{
			Metadata:       subnetworkBlock.GetMetadata(),
			Name:           types.StringDefault("", subnetworkBlock.GetMetadata()),
			EnableFlowLogs: types.BoolDefault(false, subnetworkBlock.GetMetadata()),
		}

		// logging
		if logConfigBlock := subnetworkBlock.GetBlock("log_config"); logConfigBlock.IsNotNil() {
			subnetwork.EnableFlowLogs = types.BoolExplicit(true, subnetworkBlock.GetBlock("log_config").GetMetadata())
		}

		nwAttr := subnetworkBlock.GetAttribute("network")
		if nwAttr.IsNotNil() {
			if nwblock, err := modules.GetReferencedBlock(nwAttr, subnetworkBlock); err == nil {
				if network, ok := networkMap[nwblock.ID()]; ok {
					network.Subnetworks = append(network.Subnetworks, subnetwork)
					networkMap[nwblock.ID()] = network
					continue
				}
			}
		}

		placeholder := compute.Network{
			Metadata:    types.NewUnmanagedMetadata(),
			Firewall:    nil,
			Subnetworks: nil,
		}
		placeholder.Subnetworks = append(placeholder.Subnetworks, subnetwork)
		networks = append(networks, placeholder)
	}

	for _, firewallBlock := range modules.GetResourcesByType("google_compute_firewall") {

		firewall := compute.Firewall{
			Metadata:     firewallBlock.GetMetadata(),
			Name:         firewallBlock.GetAttribute("name").AsStringValueOrDefault("", firewallBlock),
			IngressRules: nil,
			EgressRules:  nil,
		}

		for _, allowBlock := range firewallBlock.GetBlocks("allow") {
			adaptFirewallRule(&firewall, firewallBlock, allowBlock, true)
		}
		for _, denyBlock := range firewallBlock.GetBlocks("deny") {
			adaptFirewallRule(&firewall, firewallBlock, denyBlock, false)
		}

		nwAttr := firewallBlock.GetAttribute("network")
		if nwAttr.IsNotNil() {
			if nwblock, err := modules.GetReferencedBlock(nwAttr, firewallBlock); err == nil {
				if network, ok := networkMap[nwblock.ID()]; ok {
					network.Firewall = &firewall
					networkMap[nwblock.ID()] = network
					continue
				}
			}
		}

		placeholder := compute.Network{
			Metadata:    types.NewUnmanagedMetadata(),
			Firewall:    nil,
			Subnetworks: nil,
		}
		placeholder.Firewall = &firewall
		networks = append(networks, placeholder)
	}

	for _, nw := range networkMap {
		networks = append(networks, nw)
	}

	return networks
}

func expandRange(ports string, attr *terraform.Attribute) []types.IntValue {
	ports = strings.ReplaceAll(ports, " ", "")
	if !strings.Contains(ports, "-") {
		i, err := strconv.Atoi(ports)
		if err != nil {
			return nil
		}
		return []types.IntValue{
			types.Int(i, attr.GetMetadata()),
		}
	}
	parts := strings.Split(ports, "-")
	if len(parts) != 2 {
		return nil
	}
	start, err := strconv.Atoi(parts[0])
	if err != nil {
		return nil
	}
	end, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil
	}
	var output []types.IntValue
	for i := start; i <= end; i++ {
		output = append(output, types.Int(i, attr.GetMetadata()))
	}
	return output
}

func adaptFirewallRule(firewall *compute.Firewall, firewallBlock, ruleBlock *terraform.Block, allow bool) {
	protocolAttr := ruleBlock.GetAttribute("protocol")
	portsAttr := ruleBlock.GetAttribute("ports")

	var ports []types.IntValue
	for _, portStr := range portsAttr.ValueAsStrings() {
		ports = append(ports, expandRange(portStr, portsAttr)...)
	}

	// ingress by default
	isEgress := firewallBlock.GetAttribute("direction").Equals("EGRESS", terraform.IgnoreCase)

	rule := compute.FirewallRule{
		Metadata: firewallBlock.GetMetadata(),
		Enforced: types.BoolDefault(true, firewallBlock.GetMetadata()),
		IsAllow:  types.Bool(allow, ruleBlock.GetMetadata()),
		Protocol: protocolAttr.AsStringValueOrDefault("tcp", ruleBlock),
		Ports:    ports,
	}

	disabledAttr := firewallBlock.GetAttribute("disabled")
	switch {
	case disabledAttr.IsNil():
		rule.Enforced = types.BoolDefault(true, firewallBlock.GetMetadata())
	case disabledAttr.IsTrue():
		rule.Enforced = types.Bool(false, disabledAttr.GetMetadata())
	default:
		rule.Enforced = types.Bool(true, disabledAttr.GetMetadata())
	}

	if isEgress {
		var destinations []types.StringValue
		if destinationAttr := firewallBlock.GetAttribute("destination_ranges"); destinationAttr.IsNotNil() {
			for _, destination := range destinationAttr.ValueAsStrings() {
				destinations = append(destinations, types.String(destination, destinationAttr.GetMetadata()))
			}
		}
		if len(destinations) == 0 {
			destinations = append(destinations, types.StringDefault("0.0.0.0/0", firewallBlock.GetMetadata()))
		}
		firewall.EgressRules = append(firewall.EgressRules, compute.EgressRule{
			Metadata:          firewallBlock.GetMetadata(),
			FirewallRule:      rule,
			DestinationRanges: destinations,
		})
	} else {
		var sources []types.StringValue
		if sourceAttr := firewallBlock.GetAttribute("source_ranges"); sourceAttr.IsNotNil() {
			for _, source := range sourceAttr.ValueAsStrings() {
				sources = append(sources, types.String(source, sourceAttr.GetMetadata()))
			}
		}
		if len(sources) == 0 {
			sources = append(sources, types.StringDefault("0.0.0.0/0", firewallBlock.GetMetadata()))
		}
		firewall.IngressRules = append(firewall.IngressRules, compute.IngressRule{
			Metadata:     firewallBlock.GetMetadata(),
			FirewallRule: rule,
			SourceRanges: sources,
		})
	}

}
