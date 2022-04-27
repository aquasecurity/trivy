package autoscaling

import (
	"encoding/base64"

	"github.com/aquasecurity/defsec/parsers/types"

	"github.com/aquasecurity/defsec/parsers/terraform"

	"github.com/aquasecurity/defsec/providers/aws/autoscaling"
	"github.com/aquasecurity/defsec/providers/aws/ec2"
)

func Adapt(modules terraform.Modules) autoscaling.Autoscaling {
	return autoscaling.Autoscaling{
		LaunchConfigurations: adaptLaunchConfigurations(modules),
		LaunchTemplates:      adaptLaunchTemplates(modules),
	}
}

func adaptLaunchTemplates(modules terraform.Modules) (templates []autoscaling.LaunchTemplate) {

	blocks := modules.GetResourcesByType("aws_launch_template")

	for _, b := range blocks {

		metadataOptions := getMetadataOptions(b)
		userData := b.GetAttribute("user_data").AsStringValueOrDefault("", b)

		templates = append(templates, autoscaling.LaunchTemplate{
			Metadata: b.GetMetadata(),
			Instance: ec2.Instance{
				Metadata:        b.GetMetadata(),
				MetadataOptions: metadataOptions,
				UserData:        userData,
				SecurityGroups:  nil,
				RootBlockDevice: nil,
				EBSBlockDevices: nil,
			},
		})
	}

	return templates
}

func adaptLaunchConfigurations(modules terraform.Modules) []autoscaling.LaunchConfiguration {
	var launchConfigurations []autoscaling.LaunchConfiguration

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_launch_configuration") {
			launchConfig := adaptLaunchConfiguration(resource)
			for _, resource := range module.GetResourcesByType("aws_ebs_encryption_by_default") {
				if resource.GetAttribute("enabled").NotEqual(false) {
					launchConfig.RootBlockDevice.Encrypted = types.BoolDefault(true, resource.GetMetadata())
					for i := 0; i < len(launchConfig.EBSBlockDevices); i++ {
						ebs := &launchConfig.EBSBlockDevices[i]
						ebs.Encrypted = types.BoolDefault(true, resource.GetMetadata())
					}
				}
			}
			launchConfigurations = append(launchConfigurations, launchConfig)
		}
	}
	return launchConfigurations
}

func adaptLaunchConfiguration(resource *terraform.Block) autoscaling.LaunchConfiguration {
	launchConfig := autoscaling.LaunchConfiguration{
		Metadata:          resource.GetMetadata(),
		Name:              types.StringDefault("", resource.GetMetadata()),
		AssociatePublicIP: resource.GetAttribute("associate_public_ip_address").AsBoolValueOrDefault(false, resource),
		RootBlockDevice: &ec2.BlockDevice{
			Metadata:  resource.GetMetadata(),
			Encrypted: types.BoolDefault(false, resource.GetMetadata()),
		},
		EBSBlockDevices: nil,
		MetadataOptions: getMetadataOptions(resource),
		UserData:        types.StringDefault("", resource.GetMetadata()),
	}

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
		launchConfig.EBSBlockDevices = append(launchConfig.EBSBlockDevices, ec2.BlockDevice{
			Metadata:  EBSBlockDevicesBlock.GetMetadata(),
			Encrypted: encryptedVal,
		})
	}

	if userDataAttr := resource.GetAttribute("user_data"); userDataAttr.IsNotNil() {
		launchConfig.UserData = userDataAttr.AsStringValueOrDefault("", resource)
	} else if userDataBase64Attr := resource.GetAttribute("user_data_base64"); userDataBase64Attr.IsString() {
		encoded, err := base64.StdEncoding.DecodeString(userDataBase64Attr.Value().AsString())
		if err == nil {
			launchConfig.UserData = types.String(string(encoded), userDataBase64Attr.GetMetadata())
		}
	}

	return launchConfig
}

func getMetadataOptions(b *terraform.Block) ec2.MetadataOptions {
	options := ec2.MetadataOptions{
		Metadata:     b.GetMetadata(),
		HttpTokens:   types.StringDefault("", b.GetMetadata()),
		HttpEndpoint: types.StringDefault("", b.GetMetadata()),
	}

	if metadataOptions := b.GetBlock("metadata_options"); metadataOptions.IsNotNil() {
		options.Metadata = metadataOptions.GetMetadata()
		options.HttpTokens = metadataOptions.GetAttribute("http_tokens").AsStringValueOrDefault("", metadataOptions)
		options.HttpEndpoint = metadataOptions.GetAttribute("http_endpoint").AsStringValueOrDefault("", metadataOptions)
	}

	return options
}
