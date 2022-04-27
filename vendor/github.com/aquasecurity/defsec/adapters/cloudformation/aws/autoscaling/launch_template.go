package autoscaling

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/aws/autoscaling"
	"github.com/aquasecurity/defsec/providers/aws/ec2"
)

func getLaunchTemplates(file parser.FileContext) (templates []autoscaling.LaunchTemplate) {
	launchConfigResources := file.GetResourcesByType("AWS::EC2::LaunchTemplate")

	for _, r := range launchConfigResources {

		launchTemplate := autoscaling.LaunchTemplate{
			Metadata: r.Metadata(),
			Instance: ec2.Instance{
				Metadata: r.Metadata(),
				MetadataOptions: ec2.MetadataOptions{
					Metadata:     r.Metadata(),
					HttpTokens:   types.StringDefault("optional", r.Metadata()),
					HttpEndpoint: types.StringDefault("enabled", r.Metadata()),
				},
				UserData:        types.StringDefault("", r.Metadata()),
				SecurityGroups:  nil,
				RootBlockDevice: nil,
				EBSBlockDevices: nil,
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
					launchTemplate.RootBlockDevice = &copyDevice
					continue
				}
				launchTemplate.EBSBlockDevices = append(launchTemplate.EBSBlockDevices, device)
			}
		}

		templates = append(templates, launchTemplate)

	}
	return templates
}
