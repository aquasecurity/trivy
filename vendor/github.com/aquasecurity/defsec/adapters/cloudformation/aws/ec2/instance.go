package ec2

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/aws/ec2"
)

func getInstances(ctx parser.FileContext) (instances []ec2.Instance) {

	instanceResources := ctx.GetResourcesByType("AWS::EC2::Instance")

	for _, r := range instanceResources {
		instance := ec2.Instance{
			Metadata: r.Metadata(),
			// metadata not supported by CloudFormation at the moment -
			// https://github.com/aws-cloudformation/cloudformation-coverage-roadmap/issues/655
			MetadataOptions: ec2.MetadataOptions{
				Metadata:     r.Metadata(),
				HttpTokens:   types.StringDefault("optional", r.Metadata()),
				HttpEndpoint: types.StringDefault("enabled", r.Metadata()),
			},
			UserData:        r.GetStringProperty("UserData"),
			SecurityGroups:  nil,
			RootBlockDevice: nil,
			EBSBlockDevices: nil,
		}
		blockDevices := getBlockDevices(r)
		for i, device := range blockDevices {
			copyDevice := device
			if i == 0 {
				instance.RootBlockDevice = &copyDevice
				continue
			}
			instance.EBSBlockDevices = append(instance.EBSBlockDevices, device)
		}
		instances = append(instances, instance)
	}

	return instances
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
			Metadata:  d.Metadata(),
			Encrypted: result,
		}

		blockDevices = append(blockDevices, device)
	}

	return blockDevices
}
