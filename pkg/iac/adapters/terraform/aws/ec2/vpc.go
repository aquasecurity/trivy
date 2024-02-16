package ec2

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ec2"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type naclAdapter struct {
	naclRuleIDs terraform.ResourceIDResolutions
}

type sgAdapter struct {
	sgRuleIDs terraform.ResourceIDResolutions
}

func adaptVPCs(modules terraform.Modules) []ec2.VPC {
	var vpcs []ec2.VPC
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_default_vpc") {
			vpcs = append(vpcs, adaptVPC(modules, resource, true))
		}
		for _, resource := range module.GetResourcesByType("aws_vpc") {
			vpcs = append(vpcs, adaptVPC(modules, resource, false))
		}
	}
	return vpcs
}

func adaptVPC(modules terraform.Modules, block *terraform.Block, def bool) ec2.VPC {
	var hasFlowLogs bool
	for _, flow := range modules.GetResourcesByType("aws_flow_log") {
		vpcAttr := flow.GetAttribute("vpc_id")
		if vpcAttr.IsNotNil() {
			if vpcAttr.IsString() {
				if vpcAttr.Equals(block.ID()) {
					hasFlowLogs = true
					break
				}
			}
			if referencedBlock, err := modules.GetReferencedBlock(vpcAttr, flow); err == nil {
				if referencedBlock.ID() == block.ID() {
					hasFlowLogs = true
					break
				}
			}
		}
	}
	return ec2.VPC{
		Metadata:        block.GetMetadata(),
		ID:              iacTypes.StringUnresolvable(block.GetMetadata()),
		IsDefault:       iacTypes.Bool(def, block.GetMetadata()),
		SecurityGroups:  nil,
		FlowLogsEnabled: iacTypes.BoolDefault(hasFlowLogs, block.GetMetadata()),
	}
}

func (a *sgAdapter) adaptSecurityGroups(modules terraform.Modules) []ec2.SecurityGroup {
	var securityGroups []ec2.SecurityGroup
	for _, resource := range modules.GetResourcesByType("aws_security_group") {
		securityGroups = append(securityGroups, a.adaptSecurityGroup(resource, modules))
	}
	orphanResources := modules.GetResourceByIDs(a.sgRuleIDs.Orphans()...)
	if len(orphanResources) > 0 {
		orphanage := ec2.SecurityGroup{
			Metadata:     iacTypes.NewUnmanagedMetadata(),
			Description:  iacTypes.StringDefault("", iacTypes.NewUnmanagedMetadata()),
			IngressRules: nil,
			EgressRules:  nil,
			IsDefault:    iacTypes.BoolUnresolvable(iacTypes.NewUnmanagedMetadata()),
			VPCID:        iacTypes.StringUnresolvable(iacTypes.NewUnmanagedMetadata()),
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

func (a *naclAdapter) adaptNetworkACLs(modules terraform.Modules) []ec2.NetworkACL {
	var networkACLs []ec2.NetworkACL
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_network_acl") {
			networkACLs = append(networkACLs, a.adaptNetworkACL(resource, module))
		}
	}

	orphanResources := modules.GetResourceByIDs(a.naclRuleIDs.Orphans()...)
	if len(orphanResources) > 0 {
		orphanage := ec2.NetworkACL{
			Metadata:      iacTypes.NewUnmanagedMetadata(),
			Rules:         nil,
			IsDefaultRule: iacTypes.BoolDefault(false, iacTypes.NewUnmanagedMetadata()),
		}
		for _, naclRule := range orphanResources {
			orphanage.Rules = append(orphanage.Rules, adaptNetworkACLRule(naclRule))
		}
		networkACLs = append(networkACLs, orphanage)
	}

	return networkACLs
}

func (a *sgAdapter) adaptSecurityGroup(resource *terraform.Block, module terraform.Modules) ec2.SecurityGroup {
	var ingressRules []ec2.SecurityGroupRule
	var egressRules []ec2.SecurityGroupRule

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

	return ec2.SecurityGroup{
		Metadata:     resource.GetMetadata(),
		Description:  descriptionVal,
		IngressRules: ingressRules,
		EgressRules:  egressRules,
		IsDefault:    iacTypes.Bool(false, iacTypes.NewUnmanagedMetadata()),
		VPCID:        resource.GetAttribute("vpc_id").AsStringValueOrDefault("", resource),
	}
}

func adaptSGRule(resource *terraform.Block, modules terraform.Modules) ec2.SecurityGroupRule {
	ruleDescAttr := resource.GetAttribute("description")
	ruleDescVal := ruleDescAttr.AsStringValueOrDefault("", resource)

	var cidrs []iacTypes.StringValue

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
		cidrs = cidrBlocks.AsStringValues()
	}

	if ipv6cidrBlocks.IsNotNil() {
		cidrs = append(cidrs, ipv6cidrBlocks.AsStringValues()...)
	}

	return ec2.SecurityGroupRule{
		Metadata:    resource.GetMetadata(),
		Description: ruleDescVal,
		CIDRs:       cidrs,
	}
}

func (a *naclAdapter) adaptNetworkACL(resource *terraform.Block, module *terraform.Module) ec2.NetworkACL {
	var networkRules []ec2.NetworkACLRule
	rulesBlocks := module.GetReferencingResources(resource, "aws_network_acl_rule", "network_acl_id")
	for _, ruleBlock := range rulesBlocks {
		a.naclRuleIDs.Resolve(ruleBlock.ID())
		networkRules = append(networkRules, adaptNetworkACLRule(ruleBlock))
	}
	return ec2.NetworkACL{
		Metadata:      resource.GetMetadata(),
		Rules:         networkRules,
		IsDefaultRule: iacTypes.BoolDefault(false, resource.GetMetadata()),
	}
}

func adaptNetworkACLRule(resource *terraform.Block) ec2.NetworkACLRule {
	var cidrs []iacTypes.StringValue

	typeVal := iacTypes.StringDefault("ingress", resource.GetMetadata())

	egressAtrr := resource.GetAttribute("egress")
	if egressAtrr.IsTrue() {
		typeVal = iacTypes.String("egress", egressAtrr.GetMetadata())
	} else if egressAtrr.IsNotNil() {
		typeVal = iacTypes.String("ingress", egressAtrr.GetMetadata())
	}

	actionAttr := resource.GetAttribute("rule_action")
	actionVal := actionAttr.AsStringValueOrDefault("", resource)

	protocolAtrr := resource.GetAttribute("protocol")
	protocolVal := protocolAtrr.AsStringValueOrDefault("-1", resource)

	cidrAttr := resource.GetAttribute("cidr_block")
	if cidrAttr.IsNotNil() {
		cidrs = append(cidrs, cidrAttr.AsStringValueOrDefault("", resource))
	}
	ipv4cidrAttr := resource.GetAttribute("ipv6_cidr_block")
	if ipv4cidrAttr.IsNotNil() {
		cidrs = append(cidrs, ipv4cidrAttr.AsStringValueOrDefault("", resource))
	}

	return ec2.NetworkACLRule{
		Metadata: resource.GetMetadata(),
		Type:     typeVal,
		Action:   actionVal,
		Protocol: protocolVal,
		CIDRs:    cidrs,
	}
}
