package ec2

import (
	"strconv"

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

	for _, resource := range modules.GetResourcesByType("aws_default_security_group") {
		sg := a.adaptSecurityGroup(resource, modules)
		sg.IsDefault = iacTypes.Bool(true, sg.Metadata)
		sg.Description = iacTypes.String("", sg.Metadata)
		sg.VPCID = iacTypes.String("", sg.Metadata)
		securityGroups = append(securityGroups, sg)
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
				orphanage.IngressRules = append(orphanage.IngressRules, adaptSGRule(sgRule))
			} else if sgRule.GetAttribute("type").Equals("egress") {
				orphanage.EgressRules = append(orphanage.EgressRules, adaptSGRule(sgRule))
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
		ingressRules = append(ingressRules, adaptSGRule(ingressBlock))
	}

	egressBlocks := resource.GetBlocks("egress")
	for _, egressBlock := range egressBlocks {
		egressRules = append(egressRules, adaptSGRule(egressBlock))
	}

	rulesBlocks := module.GetReferencingResources(resource, "aws_security_group_rule", "security_group_id")
	for _, ruleBlock := range rulesBlocks {
		a.sgRuleIDs.Resolve(ruleBlock.ID())
		if ruleBlock.GetAttribute("type").Equals("ingress") {
			ingressRules = append(ingressRules, adaptSGRule(ruleBlock))
		} else if ruleBlock.GetAttribute("type").Equals("egress") {
			egressRules = append(egressRules, adaptSGRule(ruleBlock))
		}
	}

	for _, r := range module.GetReferencingResources(resource, "aws_vpc_security_group_ingress_rule", "security_group_id") {
		a.sgRuleIDs.Resolve(r.ID())
		ingressRules = append(ingressRules, adaptSingleSGRule(r))
	}

	for _, r := range module.GetReferencingResources(resource, "aws_vpc_security_group_egress_rule", "security_group_id") {
		a.sgRuleIDs.Resolve(r.ID())
		egressRules = append(egressRules, adaptSingleSGRule(r))
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

func adaptSGRule(resource *terraform.Block) ec2.SecurityGroupRule {
	ruleDescAttr := resource.GetAttribute("description")
	ruleDescVal := ruleDescAttr.AsStringValueOrDefault("", resource)

	var cidrs []iacTypes.StringValue

	cidrBlocks := resource.GetAttribute("cidr_blocks")
	ipv6cidrBlocks := resource.GetAttribute("ipv6_cidr_blocks")

	if cidrBlocks.IsNotNil() {
		cidrs = cidrBlocks.AsStringValues()
	}

	if ipv6cidrBlocks.IsNotNil() {
		cidrs = append(cidrs, ipv6cidrBlocks.AsStringValues()...)
	}

	protocolAddr := resource.GetAttribute("protocol")
	protocol := protocolAddr.AsStringValueOrDefault("", resource)
	if protocolAddr.IsNumber() {
		protocol = iacTypes.String(strconv.Itoa(int(protocolAddr.AsNumber())), protocolAddr.GetMetadata())
	}

	return ec2.SecurityGroupRule{
		Metadata:    resource.GetMetadata(),
		Description: ruleDescVal,
		CIDRs:       cidrs,
		FromPort:    resource.GetAttribute("from_port").AsIntValueOrDefault(-1, resource),
		ToPort:      resource.GetAttribute("to_port").AsIntValueOrDefault(-1, resource),
		Protocol:    protocol,
	}
}

func adaptSingleSGRule(resource *terraform.Block) ec2.SecurityGroupRule {
	description := resource.GetAttribute("description").AsStringValueOrDefault("", resource)

	var cidrs []iacTypes.StringValue
	if ipv4 := resource.GetAttribute("cidr_ipv4"); ipv4.IsNotNil() {
		cidrs = append(cidrs, ipv4.AsStringValueOrDefault("", resource))
	}
	if ipv6 := resource.GetAttribute("cidr_ipv6"); ipv6.IsNotNil() {
		cidrs = append(cidrs, ipv6.AsStringValueOrDefault("", resource))
	}

	return ec2.SecurityGroupRule{
		Metadata:    resource.GetMetadata(),
		Description: description,
		CIDRs:       cidrs,
		FromPort:    resource.GetAttribute("from_port").AsIntValueOrDefault(-1, resource),
		ToPort:      resource.GetAttribute("to_port").AsIntValueOrDefault(-1, resource),
		Protocol:    resource.GetAttribute("ip_protocol").AsStringValueOrDefault("", resource),
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
	protocolVal := protocolAtrr.AsStringValueOrDefault("", resource)

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
		FromPort: resource.GetAttribute("from_port").AsIntValueOrDefault(-1, resource),
		ToPort:   resource.GetAttribute("to_port").AsIntValueOrDefault(-1, resource),
	}
}
