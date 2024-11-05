package ec2

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ec2"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func getLaunchTemplates(file parser.FileContext) (templates []ec2.LaunchTemplate) {
	launchConfigResources := file.GetResourcesByType("AWS::EC2::LaunchTemplate")

	for _, r := range launchConfigResources {
		templates = append(templates, adaptLaunchTemplate(r))
	}
	return templates
}

func adaptLaunchTemplate(r *parser.Resource) ec2.LaunchTemplate {
	launchTemplate := ec2.LaunchTemplate{
		Metadata: r.Metadata(),
		Name:     r.GetStringProperty("LaunchTemplateName", ""),
		Instance: ec2.Instance{
			Metadata: r.Metadata(),
			MetadataOptions: ec2.MetadataOptions{
				Metadata:     r.Metadata(),
				HttpTokens:   types.StringDefault("optional", r.Metadata()),
				HttpEndpoint: types.StringDefault("enabled", r.Metadata()),
			},
			UserData: types.StringDefault("", r.Metadata()),
		},
	}

	if data := r.GetProperty("LaunchTemplateData"); data.IsNotNil() {
		if opts := data.GetProperty("MetadataOptions"); opts.IsNotNil() {
			launchTemplate.MetadataOptions = ec2.MetadataOptions{
				Metadata:     opts.Metadata(),
				HttpTokens:   opts.GetStringProperty("HttpTokens", "optional"),
				HttpEndpoint: opts.GetStringProperty("HttpEndpoint", "enabled"),
			}
		}

		launchTemplate.Instance.UserData = data.GetStringProperty("UserData", "")

		blockDevices := getBlockDevices(r)
		for i, device := range blockDevices {
			copyDevice := device
			if i == 0 {
				launchTemplate.RootBlockDevice = copyDevice
			} else {
				launchTemplate.EBSBlockDevices = append(launchTemplate.EBSBlockDevices, device)
			}
		}
	}

	return launchTemplate
}
