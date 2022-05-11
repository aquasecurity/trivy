package vpc

import (
	"github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/providers/aws/vpc"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) vpc.VPC {

	naclAdapter := naclAdapter{naclRuleIDs: modules.GetChildResourceIDMapByType("aws_network_acl_rule")}
	sgAdapter := sgAdapter{sgRuleIDs: modules.GetChildResourceIDMapByType("aws_security_group_rule")}

	rx := vpc.VPC{
		DefaultVPCs:    adaptDefaultVPCs(modules),
		SecurityGroups: sgAdapter.adaptSecurityGroups(modules),
		NetworkACLs:    naclAdapter.adaptNetworkACLs(modules),
	}
	return rx
}

type naclAdapter struct {
	naclRuleIDs terraform.ResourceIDResolutions
}

type sgAdapter struct {
	sgRuleIDs terraform.ResourceIDResolutions
}

func adaptDefaultVPCs(modules terraform.Modules) []vpc.DefaultVPC {
	var defaultVPCs []vpc.DefaultVPC
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_default_vpc") {
			defaultVPCs = append(defaultVPCs, vpc.DefaultVPC{
				Metadata: resource.GetMetadata(),
			})
		}
	}
	return defaultVPCs
}

func (a *sgAdapter) adaptSecurityGroups(modules terraform.Modules) []vpc.SecurityGroup {
	var securityGroups []vpc.SecurityGroup
	for _, resource := range modules.GetResourcesByType("aws_security_group") {
		securityGroups = append(securityGroups, a.adaptSecurityGroup(resource, modules))
	}
	orphanResources := modules.GetResourceByIDs(a.sgRuleIDs.Orphans()...)
	if len(orphanResources) > 0 {
		orphanage := vpc.SecurityGroup{
			Metadata:     types.NewUnmanagedMetadata(),
			Description:  types.StringDefault("", types.NewUnmanagedMetadata()),
			IngressRules: nil,
			EgressRules:  nil,
		}
		for _, sgRule := range orphanResources {
			if sgRule.GetAttribute("type").Equals("ingress") {
				orphanage.IngressRules = append(orphanage.IngressRules, adaptSGRule(sgRule, modules))
			} else if sgRule.GetAttribute("type").Equals("egress") {
				orphanage.EgressRules = append(orphanage.EgressRules, adaptSGRule(sgRule, modules))
			}
		}
		securityGroups = append(securityGroups, orphanage)
	}

	return securityGroups
}

func (a *naclAdapter) adaptNetworkACLs(modules terraform.Modules) []vpc.NetworkACL {
	var networkACLs []vpc.NetworkACL
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_network_acl") {
			networkACLs = append(networkACLs, a.adaptNetworkACL(resource, module))
		}
	}

	orphanResources := modules.GetResourceByIDs(a.naclRuleIDs.Orphans()...)
	if len(orphanResources) > 0 {
		orphanage := vpc.NetworkACL{
			Metadata: types.NewUnmanagedMetadata(),
			Rules:    nil,
		}
		for _, naclRule := range orphanResources {
			orphanage.Rules = append(orphanage.Rules, adaptNetworkACLRule(naclRule))
		}
		networkACLs = append(networkACLs, orphanage)
	}

	return networkACLs
}

func (a *sgAdapter) adaptSecurityGroup(resource *terraform.Block, module terraform.Modules) vpc.SecurityGroup {
	var ingressRules []vpc.SecurityGroupRule
	var egressRules []vpc.SecurityGroupRule

	descriptionAttr := resource.GetAttribute("description")
	descriptionVal := descriptionAttr.AsStringValueOrDefault("Managed by Terraform", resource)

	ingressBlocks := resource.GetBlocks("ingress")
	for _, ingressBlock := range ingressBlocks {
		ingressRules = append(ingressRules, adaptSGRule(ingressBlock, module))
	}

	egressBlocks := resource.GetBlocks("egress")
	for _, egressBlock := range egressBlocks {
		egressRules = append(egressRules, adaptSGRule(egressBlock, module))
	}

	rulesBlocks := module.GetReferencingResources(resource, "aws_security_group_rule", "security_group_id")
	for _, ruleBlock := range rulesBlocks {
		a.sgRuleIDs.Resolve(ruleBlock.ID())
		if ruleBlock.GetAttribute("type").Equals("ingress") {
			ingressRules = append(ingressRules, adaptSGRule(ruleBlock, module))
		} else if ruleBlock.GetAttribute("type").Equals("egress") {
			egressRules = append(egressRules, adaptSGRule(ruleBlock, module))
		}
	}

	return vpc.SecurityGroup{
		Metadata:     resource.GetMetadata(),
		Description:  descriptionVal,
		IngressRules: ingressRules,
		EgressRules:  egressRules,
	}
}

func adaptSGRule(resource *terraform.Block, modules terraform.Modules) vpc.SecurityGroupRule {
	ruleDescAttr := resource.GetAttribute("description")
	ruleDescVal := ruleDescAttr.AsStringValueOrDefault("", resource)

	var cidrs []types.StringValue

	cidrBlocks := resource.GetAttribute("cidr_blocks")
	ipv6cidrBlocks := resource.GetAttribute("ipv6_cidr_blocks")
	varBlocks := modules.GetBlocks().OfType("variable")

	for _, vb := range varBlocks {
		if cidrBlocks.IsNotNil() && cidrBlocks.ReferencesBlock(vb) {
			cidrBlocks = vb.GetAttribute("default")
		}
		if ipv6cidrBlocks.IsNotNil() && ipv6cidrBlocks.ReferencesBlock(vb) {
			ipv6cidrBlocks = vb.GetAttribute("default")
		}
	}

	if cidrBlocks.IsNotNil() {
		cidrsList := cidrBlocks.ValueAsStrings()
		for _, cidr := range cidrsList {
			cidrs = append(cidrs, types.String(cidr, cidrBlocks.GetMetadata()))
		}
	} else {
		cidrs = append(cidrs, cidrBlocks.AsStringValueOrDefault("", resource))
	}

	if ipv6cidrBlocks.IsNotNil() {
		cidrsList := ipv6cidrBlocks.ValueAsStrings()
		for _, cidr := range cidrsList {
			cidrs = append(cidrs, types.String(cidr, ipv6cidrBlocks.GetMetadata()))
		}
	} else {
		cidrs = append(cidrs, ipv6cidrBlocks.AsStringValueOrDefault("", resource))
	}

	return vpc.SecurityGroupRule{
		Metadata:    resource.GetMetadata(),
		Description: ruleDescVal,
		CIDRs:       cidrs,
	}
}

func (a *naclAdapter) adaptNetworkACL(resource *terraform.Block, module *terraform.Module) vpc.NetworkACL {
	var networkRules []vpc.NetworkACLRule
	rulesBlocks := module.GetReferencingResources(resource, "aws_network_acl_rule", "network_acl_id")
	for _, ruleBlock := range rulesBlocks {
		a.naclRuleIDs.Resolve(ruleBlock.ID())
		networkRules = append(networkRules, adaptNetworkACLRule(ruleBlock))
	}
	return vpc.NetworkACL{
		Metadata: resource.GetMetadata(),
		Rules:    networkRules,
	}
}

func adaptNetworkACLRule(resource *terraform.Block) vpc.NetworkACLRule {
	var cidrs []types.StringValue

	typeVal := types.StringDefault("ingress", resource.GetMetadata())

	egressAtrr := resource.GetAttribute("egress")
	if egressAtrr.IsTrue() {
		typeVal = types.String("egress", resource.GetMetadata())
	}

	actionAttr := resource.GetAttribute("rule_action")
	actionVal := actionAttr.AsStringValueOrDefault("", resource)

	protocolAtrr := resource.GetAttribute("protocol")
	protocolVal := protocolAtrr.AsStringValueOrDefault("-1", resource)

	cidrAttr := resource.GetAttribute("cidr_block")
	ipv4cidrAttr := resource.GetAttribute("ipv6_cidr_block")
	cidrs = append(cidrs, cidrAttr.AsStringValueOrDefault("", resource))
	cidrs = append(cidrs, ipv4cidrAttr.AsStringValueOrDefault("", resource))

	return vpc.NetworkACLRule{
		Metadata: resource.GetMetadata(),
		Type:     typeVal,
		Action:   actionVal,
		Protocol: protocolVal,
		CIDRs:    cidrs,
	}
}
