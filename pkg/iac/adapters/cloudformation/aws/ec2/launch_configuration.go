package ec2

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ec2"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func getLaunchConfigurations(file parser.FileContext) (launchConfigurations []ec2.LaunchConfiguration) {
	launchConfigResources := file.GetResourcesByType("AWS::AutoScaling::LaunchConfiguration")

	for _, r := range launchConfigResources {

		launchConfig := ec2.LaunchConfiguration{
			Metadata:          r.Metadata(),
			Name:              r.GetStringProperty("LaunchConfigurationName"),
			AssociatePublicIP: r.GetBoolProperty("AssociatePublicIpAddress"),
			MetadataOptions: ec2.MetadataOptions{
				Metadata:     r.Metadata(),
				HttpTokens:   types.StringDefault("optional", r.Metadata()),
				HttpEndpoint: types.StringDefault("enabled", r.Metadata()),
			},
			UserData: r.GetStringProperty("UserData"),
		}

		if opts := r.GetProperty("MetadataOptions"); opts.IsNotNil() {
			launchConfig.MetadataOptions = ec2.MetadataOptions{
				Metadata:     opts.Metadata(),
				HttpTokens:   opts.GetStringProperty("HttpTokens", "optional"),
				HttpEndpoint: opts.GetStringProperty("HttpEndpoint", "enabled"),
			}
		}

		blockDevices := getBlockDevices(r)
		for i, device := range blockDevices {
			copyDevice := device
			if i == 0 {
				launchConfig.RootBlockDevice = copyDevice
				continue
			}
			launchConfig.EBSBlockDevices = append(launchConfig.EBSBlockDevices, device)
		}

		launchConfigurations = append(launchConfigurations, launchConfig)

	}
	return launchConfigurations
}
