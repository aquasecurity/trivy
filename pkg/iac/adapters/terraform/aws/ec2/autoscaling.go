package ec2

import (
	"encoding/base64"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ec2"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func adaptLaunchTemplates(modules terraform.Modules) (templates []ec2.LaunchTemplate) {

	blocks := modules.GetResourcesByType("aws_launch_template")

	for _, b := range blocks {
		templates = append(templates, adaptLaunchTemplate(b))
	}

	return templates
}

func adaptLaunchTemplate(b *terraform.Block) ec2.LaunchTemplate {
	return ec2.LaunchTemplate{
		Metadata: b.GetMetadata(),
		Instance: ec2.Instance{
			Metadata:        b.GetMetadata(),
			MetadataOptions: getMetadataOptions(b),
			UserData:        b.GetAttribute("user_data").AsStringValueOrDefault("", b),
		},
	}
}

func adaptLaunchConfigurations(modules terraform.Modules) []ec2.LaunchConfiguration {
	var launchConfigurations []ec2.LaunchConfiguration

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_launch_configuration") {
			launchConfig := adaptLaunchConfiguration(resource)
			for _, resource := range module.GetResourcesByType("aws_ebs_encryption_by_default") {
				if resource.GetAttribute("enabled").NotEqual(false) {
					launchConfig.RootBlockDevice.Encrypted = iacTypes.BoolDefault(true, resource.GetMetadata())
					for i := 0; i < len(launchConfig.EBSBlockDevices); i++ {
						ebs := launchConfig.EBSBlockDevices[i]
						ebs.Encrypted = iacTypes.BoolDefault(true, resource.GetMetadata())
					}
				}
			}
			launchConfigurations = append(launchConfigurations, launchConfig)
		}
	}
	return launchConfigurations
}

func adaptLaunchConfiguration(resource *terraform.Block) ec2.LaunchConfiguration {
	launchConfig := ec2.LaunchConfiguration{
		Metadata:          resource.GetMetadata(),
		Name:              iacTypes.StringDefault("", resource.GetMetadata()),
		AssociatePublicIP: resource.GetAttribute("associate_public_ip_address").AsBoolValueOrDefault(false, resource),
		RootBlockDevice: &ec2.BlockDevice{
			Metadata:  resource.GetMetadata(),
			Encrypted: iacTypes.BoolDefault(false, resource.GetMetadata()),
		},
		EBSBlockDevices: nil,
		MetadataOptions: getMetadataOptions(resource),
		UserData:        iacTypes.StringDefault("", resource.GetMetadata()),
	}

	//#nosec G101 -- False positive
	if resource.TypeLabel() == "aws_launch_configuration" {
		nameAttr := resource.GetAttribute("name")
		launchConfig.Name = nameAttr.AsStringValueOrDefault("", resource)
	}

	if rootBlockDeviceBlock := resource.GetBlock("root_block_device"); rootBlockDeviceBlock.IsNotNil() {
		encryptedAttr := rootBlockDeviceBlock.GetAttribute("encrypted")
		launchConfig.RootBlockDevice.Encrypted = encryptedAttr.AsBoolValueOrDefault(false, rootBlockDeviceBlock)
		launchConfig.RootBlockDevice.Metadata = rootBlockDeviceBlock.GetMetadata()
	}

	EBSBlockDevicesBlocks := resource.GetBlocks("ebs_block_device")
	for _, EBSBlockDevicesBlock := range EBSBlockDevicesBlocks {
		encryptedAttr := EBSBlockDevicesBlock.GetAttribute("encrypted")
		encryptedVal := encryptedAttr.AsBoolValueOrDefault(false, EBSBlockDevicesBlock)
		launchConfig.EBSBlockDevices = append(launchConfig.EBSBlockDevices, &ec2.BlockDevice{
			Metadata:  EBSBlockDevicesBlock.GetMetadata(),
			Encrypted: encryptedVal,
		})
	}

	if userDataAttr := resource.GetAttribute("user_data"); userDataAttr.IsNotNil() {
		launchConfig.UserData = userDataAttr.AsStringValueOrDefault("", resource)
	} else if userDataBase64Attr := resource.GetAttribute("user_data_base64"); userDataBase64Attr.IsString() {
		encoded, err := base64.StdEncoding.DecodeString(userDataBase64Attr.Value().AsString())
		if err == nil {
			launchConfig.UserData = iacTypes.String(string(encoded), userDataBase64Attr.GetMetadata())
		}
	}

	return launchConfig
}

func getMetadataOptions(b *terraform.Block) ec2.MetadataOptions {
	options := ec2.MetadataOptions{
		Metadata:     b.GetMetadata(),
		HttpTokens:   iacTypes.StringDefault("", b.GetMetadata()),
		HttpEndpoint: iacTypes.StringDefault("", b.GetMetadata()),
	}

	if metadataOptions := b.GetBlock("metadata_options"); metadataOptions.IsNotNil() {
		options.Metadata = metadataOptions.GetMetadata()
		options.HttpTokens = metadataOptions.GetAttribute("http_tokens").AsStringValueOrDefault("", metadataOptions)
		options.HttpEndpoint = metadataOptions.GetAttribute("http_endpoint").AsStringValueOrDefault("", metadataOptions)
	}

	return options
}
