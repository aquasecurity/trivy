package ec2

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ec2"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func Adapt(modules terraform.Modules) ec2.EC2 {

	naclAdapter := naclAdapter{naclRuleIDs: modules.GetChildResourceIDMapByType("aws_network_acl_rule")}
	sgAdapter := sgAdapter{sgRuleIDs: modules.GetChildResourceIDMapByType("aws_security_group_rule")}

	return ec2.EC2{
		Instances:            getInstances(modules),
		VPCs:                 adaptVPCs(modules),
		SecurityGroups:       sgAdapter.adaptSecurityGroups(modules),
		Subnets:              adaptSubnets(modules),
		NetworkACLs:          naclAdapter.adaptNetworkACLs(modules),
		LaunchConfigurations: adaptLaunchConfigurations(modules),
		LaunchTemplates:      adaptLaunchTemplates(modules),
		Volumes:              adaptVolumes(modules),
	}
}

func getInstances(modules terraform.Modules) []ec2.Instance {
	var instances []ec2.Instance

	blocks := modules.GetResourcesByType("aws_instance")

	for _, b := range blocks {
		instance := ec2.Instance{
			Metadata:        b.GetMetadata(),
			MetadataOptions: getMetadataOptions(b),
			UserData:        b.GetAttribute("user_data").AsStringValueOrDefault("", b),
		}

		if launchTemplate := findRelatedLaunchTemplate(modules, b); launchTemplate != nil {
			instance = launchTemplate.Instance
		}

		if instance.RootBlockDevice == nil {
			instance.RootBlockDevice = &ec2.BlockDevice{
				Metadata:  b.GetMetadata(),
				Encrypted: types.BoolDefault(false, b.GetMetadata()),
			}
		}

		if rootBlockDevice := b.GetBlock("root_block_device"); rootBlockDevice.IsNotNil() {
			instance.RootBlockDevice = &ec2.BlockDevice{
				Metadata:  rootBlockDevice.GetMetadata(),
				Encrypted: rootBlockDevice.GetAttribute("encrypted").AsBoolValueOrDefault(false, b),
			}
		}

		for _, ebsBlock := range b.GetBlocks("ebs_block_device") {
			instance.EBSBlockDevices = append(instance.EBSBlockDevices, &ec2.BlockDevice{
				Metadata:  ebsBlock.GetMetadata(),
				Encrypted: ebsBlock.GetAttribute("encrypted").AsBoolValueOrDefault(false, b),
			})
		}

		for _, resource := range modules.GetResourcesByType("aws_ebs_encryption_by_default") {
			if resource.GetAttribute("enabled").NotEqual(false) {
				instance.RootBlockDevice.Encrypted = types.BoolDefault(true, resource.GetMetadata())
				for i := 0; i < len(instance.EBSBlockDevices); i++ {
					ebs := instance.EBSBlockDevices[i]
					ebs.Encrypted = types.BoolDefault(true, resource.GetMetadata())
				}
			}
		}

		instances = append(instances, instance)
	}

	return instances
}

func findRelatedLaunchTemplate(modules terraform.Modules, instanceBlock *terraform.Block) *ec2.LaunchTemplate {
	launchTemplateBlock := instanceBlock.GetBlock("launch_template")
	if launchTemplateBlock.IsNil() {
		return nil
	}

	templateRef := launchTemplateBlock.GetAttribute("name")

	if !templateRef.IsResolvable() {
		templateRef = launchTemplateBlock.GetAttribute("id")
	}

	if templateRef.IsString() {
		for _, r := range modules.GetResourcesByType("aws_launch_template") {
			templateName := r.GetAttribute("name").AsStringValueOrDefault("", r).Value()
			if templateRef.Equals(r.ID()) || templateRef.Equals(templateName) {
				launchTemplate := adaptLaunchTemplate(r)
				return &launchTemplate
			}
		}
	}

	return nil
}
