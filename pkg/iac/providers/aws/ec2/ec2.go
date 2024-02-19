package ec2

type EC2 struct {
	Instances            []Instance
	LaunchConfigurations []LaunchConfiguration
	LaunchTemplates      []LaunchTemplate
	VPCs                 []VPC
	SecurityGroups       []SecurityGroup
	NetworkACLs          []NetworkACL
	Subnets              []Subnet
	Volumes              []Volume
}
