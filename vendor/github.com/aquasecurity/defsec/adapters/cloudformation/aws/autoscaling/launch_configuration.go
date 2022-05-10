package autoscaling

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/aws/autoscaling"
	"github.com/aquasecurity/defsec/providers/aws/ec2"
)

func getLaunchConfigurations(file parser.FileContext) (launchConfigurations []autoscaling.LaunchConfiguration) {
	launchConfigResources := file.GetResourceByType("AWS::AutoScaling::LaunchConfiguration")

	for _, r := range launchConfigResources {

		launchConfig := autoscaling.LaunchConfiguration{
			Metadata:          r.Metadata(),
			Name:              r.GetStringProperty("Name"),
			AssociatePublicIP: r.GetBoolProperty("AssociatePublicIpAddress"),
			EBSBlockDevices:   []ec2.BlockDevice{},
		}

		blockDevices := getBlockDevices(r)
		for i, device := range blockDevices {
			copyDevice := device
			if i == 0 {
				launchConfig.RootBlockDevice = &copyDevice
				continue
			}
			launchConfig.EBSBlockDevices = append(launchConfig.EBSBlockDevices, device)
		}

		launchConfigurations = append(launchConfigurations, launchConfig)

	}
	return launchConfigurations
}

func getBlockDevices(r *parser.Resource) []ec2.BlockDevice {
	var blockDevices []ec2.BlockDevice

	devicesProp := r.GetProperty("BlockDeviceMappings")

	if devicesProp.IsNil() {
		return blockDevices
	}

	for _, d := range devicesProp.AsList() {
		encrypted := d.GetProperty("Ebs.Encrypted")
		var result types.BoolValue
		if encrypted.IsNil() {
			result = types.BoolDefault(false, d.Metadata())
		} else {
			result = encrypted.AsBoolValue()
		}

		device := ec2.BlockDevice{
			Encrypted: result,
		}

		blockDevices = append(blockDevices, device)
	}

	return blockDevices
}
