package ec2

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ec2"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
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
				HttpTokens:   iacTypes.StringDefault("optional", r.Metadata()),
				HttpEndpoint: iacTypes.StringDefault("enabled", r.Metadata()),
			},
			UserData: r.GetStringProperty("UserData"),
		}

		if launchTemplate, ok := findRelatedLaunchTemplate(ctx, r); ok {
			instance = launchTemplate.Instance
		}

		if instance.RootBlockDevice == nil {
			instance.RootBlockDevice = &ec2.BlockDevice{
				Metadata:  r.Metadata(),
				Encrypted: iacTypes.BoolDefault(false, r.Metadata()),
			}
		}

		blockDevices := getBlockDevices(r)
		for i, device := range blockDevices {
			copyDevice := device
			if i == 0 {
				instance.RootBlockDevice = copyDevice
				continue
			}
			instance.EBSBlockDevices = append(instance.EBSBlockDevices, device)
		}
		instances = append(instances, instance)
	}

	return instances
}

func findRelatedLaunchTemplate(fctx parser.FileContext, r *parser.Resource) (ec2.LaunchTemplate, bool) {
	launchTemplateRef := r.GetProperty("LaunchTemplate.LaunchTemplateName")
	if launchTemplateRef.IsString() {
		res := findLaunchTemplateByName(fctx, launchTemplateRef)
		if res != nil {
			return adaptLaunchTemplate(res), true
		}
	}

	launchTemplateRef = r.GetProperty("LaunchTemplate.LaunchTemplateId")
	if !launchTemplateRef.IsString() {
		return ec2.LaunchTemplate{}, false
	}

	resource := fctx.GetResourceByLogicalID(launchTemplateRef.AsString())
	if resource == nil {
		return ec2.LaunchTemplate{}, false
	}
	return adaptLaunchTemplate(resource), true
}

func findLaunchTemplateByName(fctx parser.FileContext, prop *parser.Property) *parser.Resource {
	for _, res := range fctx.GetResourcesByType("AWS::EC2::LaunchTemplate") {
		templateName := res.GetProperty("LaunchTemplateName")
		if templateName.IsNotString() {
			continue
		}

		if prop.EqualTo(templateName.AsString()) {
			return res
		}
	}

	return nil
}

func getBlockDevices(r *parser.Resource) []*ec2.BlockDevice {
	var blockDevices []*ec2.BlockDevice

	devicesProp := r.GetProperty("BlockDeviceMappings")

	if devicesProp.IsNil() {
		return blockDevices
	}

	for _, d := range devicesProp.AsList() {
		device := &ec2.BlockDevice{
			Metadata:  d.Metadata(),
			Encrypted: d.GetBoolProperty("Ebs.Encrypted"),
		}

		blockDevices = append(blockDevices, device)
	}

	return blockDevices
}
