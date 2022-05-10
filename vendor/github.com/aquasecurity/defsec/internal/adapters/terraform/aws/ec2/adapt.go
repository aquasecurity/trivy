package ec2

import (
	"github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/providers/aws/ec2"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) ec2.EC2 {
	return ec2.EC2{
		Instances: getInstances(modules),
	}
}

func getInstances(modules terraform.Modules) []ec2.Instance {
	var instances []ec2.Instance

	blocks := modules.GetResourcesByType("aws_instance")

	for _, b := range blocks {

		metadataOptions := getMetadataOptions(b)
		userData := b.GetAttribute("user_data").AsStringValueOrDefault("", b)

		instance := ec2.Instance{
			Metadata:        b.GetMetadata(),
			MetadataOptions: metadataOptions,
			UserData:        userData,
			SecurityGroups:  nil,
			RootBlockDevice: &ec2.BlockDevice{
				Metadata:  b.GetMetadata(),
				Encrypted: types.BoolDefault(false, b.GetMetadata()),
			},
			EBSBlockDevices: nil,
		}

		if rootBlockDevice := b.GetBlock("root_block_device"); rootBlockDevice.IsNotNil() {
			instance.RootBlockDevice.Metadata = rootBlockDevice.GetMetadata()
			instance.RootBlockDevice.Encrypted = rootBlockDevice.GetAttribute("encrypted").AsBoolValueOrDefault(false, b)
		}

		for _, ebsBlock := range b.GetBlocks("ebs_block_device") {
			instance.EBSBlockDevices = append(instance.EBSBlockDevices, ec2.BlockDevice{
				Metadata:  ebsBlock.GetMetadata(),
				Encrypted: ebsBlock.GetAttribute("encrypted").AsBoolValueOrDefault(false, b),
			})
		}

		for _, resource := range modules.GetResourcesByType("aws_ebs_encryption_by_default") {
			if resource.GetAttribute("enabled").NotEqual(false) {
				instance.RootBlockDevice.Encrypted = types.BoolDefault(true, resource.GetMetadata())
				for i := 0; i < len(instance.EBSBlockDevices); i++ {
					ebs := &instance.EBSBlockDevices[i]
					ebs.Encrypted = types.BoolDefault(true, resource.GetMetadata())
				}
			}
		}

		instances = append(instances, instance)
	}

	return instances
}

func getMetadataOptions(b *terraform.Block) ec2.MetadataOptions {

	if metadataOptions := b.GetBlock("metadata_options"); metadataOptions.IsNotNil() {
		metaOpts := ec2.MetadataOptions{
			Metadata:     metadataOptions.GetMetadata(),
			HttpTokens:   metadataOptions.GetAttribute("http_tokens").AsStringValueOrDefault("", metadataOptions),
			HttpEndpoint: metadataOptions.GetAttribute("http_endpoint").AsStringValueOrDefault("", metadataOptions),
		}
		return metaOpts
	}

	return ec2.MetadataOptions{
		Metadata:     b.GetMetadata(),
		HttpTokens:   types.StringDefault("", b.GetMetadata()),
		HttpEndpoint: types.StringDefault("", b.GetMetadata()),
	}
}
