package network

import (
	"github.com/aquasecurity/trivy/pkg/iac/adapters/common"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/network"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func AdaptSGRule(ruleBlock *terraform.Block) network.SecurityGroupRule {

	rule := network.SecurityGroupRule{
		Metadata:             ruleBlock.GetMetadata(),
		Outbound:             iacTypes.BoolDefault(false, ruleBlock.GetMetadata()),
		Allow:                iacTypes.BoolDefault(true, ruleBlock.GetMetadata()),
		SourceAddresses:      nil,
		SourcePorts:          nil,
		DestinationAddresses: nil,
		DestinationPorts:     nil,
		Protocol:             ruleBlock.GetAttribute("protocol").AsStringValueOrDefault("", ruleBlock),
	}

	accessAttr := ruleBlock.GetAttribute("access")
	if accessAttr.Equals("Allow") {
		rule.Allow = iacTypes.Bool(true, accessAttr.GetMetadata())
	} else if accessAttr.Equals("Deny") {
		rule.Allow = iacTypes.Bool(false, accessAttr.GetMetadata())
	}

	directionAttr := ruleBlock.GetAttribute("direction")
	if directionAttr.Equals("Inbound") {
		rule.Outbound = iacTypes.Bool(false, directionAttr.GetMetadata())
	} else if directionAttr.Equals("Outbound") {
		rule.Outbound = iacTypes.Bool(true, directionAttr.GetMetadata())
	}

	adaptSource(ruleBlock, &rule)
	adaptDestination(ruleBlock, &rule)

	return rule
}

func adaptSource(ruleBlock *terraform.Block, rule *network.SecurityGroupRule) {
	if sourceAddressAttr := ruleBlock.GetAttribute("source_address_prefix"); sourceAddressAttr.IsString() {
		rule.SourceAddresses = append(rule.SourceAddresses, sourceAddressAttr.AsStringValueOrDefault("", ruleBlock))
	} else if sourceAddressPrefixesAttr := ruleBlock.GetAttribute("source_address_prefixes"); sourceAddressPrefixesAttr.IsNotNil() {
		rule.SourceAddresses = append(rule.SourceAddresses, sourceAddressPrefixesAttr.AsStringValues()...)
	}

	if sourcePortRangesAttr := ruleBlock.GetAttribute("source_port_ranges"); sourcePortRangesAttr.IsNotNil() {
		ports := sourcePortRangesAttr.AsStringValues()
		for _, value := range ports {
			rng := parsePortRange(value.Value(), value.GetMetadata())
			if rng.Valid() {
				rule.SourcePorts = append(rule.SourcePorts, rng)
			}
		}
	} else if sourcePortRangeAttr := ruleBlock.GetAttribute("source_port_range"); sourcePortRangeAttr.IsString() {
		rng := parsePortRange(sourcePortRangeAttr.Value().AsString(), sourcePortRangeAttr.GetMetadata())
		if rng.Valid() {
			rule.SourcePorts = append(rule.SourcePorts, rng)
		}
	} else if sourcePortRangeAttr := ruleBlock.GetAttribute("source_port_range"); sourcePortRangeAttr.IsNumber() {
		f := sourcePortRangeAttr.AsNumber()
		rule.SourcePorts = append(rule.SourcePorts, common.PortRange{
			Metadata: sourcePortRangeAttr.GetMetadata(),
			Start:    iacTypes.Int(int(f), sourcePortRangeAttr.GetMetadata()),
			End:      iacTypes.Int(int(f), sourcePortRangeAttr.GetMetadata()),
		})
	}
}

func adaptDestination(ruleBlock *terraform.Block, rule *network.SecurityGroupRule) {
	if destAddressAttr := ruleBlock.GetAttribute("destination_address_prefix"); destAddressAttr.IsString() {
		rule.DestinationAddresses = append(rule.DestinationAddresses, destAddressAttr.AsStringValueOrDefault("", ruleBlock))
	} else if destAddressPrefixesAttr := ruleBlock.GetAttribute("destination_address_prefixes"); destAddressPrefixesAttr.IsNotNil() {
		rule.DestinationAddresses = append(rule.DestinationAddresses, destAddressPrefixesAttr.AsStringValues()...)
	}

	if destPortRangesAttr := ruleBlock.GetAttribute("destination_port_ranges"); destPortRangesAttr.IsNotNil() {
		ports := destPortRangesAttr.AsStringValues()
		for _, value := range ports {
			rng := parsePortRange(value.Value(), destPortRangesAttr.GetMetadata())
			if rng.Valid() {
				rule.DestinationPorts = append(rule.DestinationPorts, rng)
			}
		}
	} else if destPortRangeAttr := ruleBlock.GetAttribute("destination_port_range"); destPortRangeAttr.IsString() {
		rng := parsePortRange(destPortRangeAttr.Value().AsString(), destPortRangeAttr.GetMetadata())
		if rng.Valid() {
			rule.DestinationPorts = append(rule.DestinationPorts, rng)
		}
	} else if destPortRangeAttr := ruleBlock.GetAttribute("destination_port_range"); destPortRangeAttr.IsNumber() {
		f := destPortRangeAttr.AsNumber()
		rule.DestinationPorts = append(rule.DestinationPorts, common.PortRange{
			Metadata: destPortRangeAttr.GetMetadata(),
			Start:    iacTypes.Int(int(f), destPortRangeAttr.GetMetadata()),
			End:      iacTypes.Int(int(f), destPortRangeAttr.GetMetadata()),
		})
	}
}
