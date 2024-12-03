package ec2

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ec2"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func TestAdapt(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected ec2.EC2
	}{
		{
			name: "complete",
			source: `AWSTemplateFormatVersion: 2010-09-09
Resources:
  MyEC2Instance:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: "ami-79fd7eee"
      KeyName: "testkey"
      BlockDeviceMappings:
      - DeviceName: "/dev/sdm"
        Ebs:
          VolumeType: "io1"
          Iops: "200"
          DeleteOnTermination: "false"
          VolumeSize: "20"
          Encrypted: true
      - DeviceName: "/dev/sdk"
        NoDevice: {}
  NewVolume:
    Type: AWS::EC2::Volume
    Properties: 
      KmsKeyId: alias/my_cmk
      Encrypted: true
  mySubnet:
    Type: AWS::EC2::Subnet
    Properties:
      MapPublicIpOnLaunch: true
  InstanceSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupName: default
      GroupDescription: Allow http to client host
      VpcId: vpc-id
      SecurityGroupIngress:
        - IpProtocol: tcp
          Description: ingress
          FromPort: "80"
          ToPort: 80
          CidrIp: 0.0.0.0/0
      SecurityGroupEgress:
        - IpProtocol: -1
          Description: egress
          FromPort: 80
          ToPort: "80"
          CidrIp: "0.0.0.0/0"
  myNetworkAcl:
      Type: AWS::EC2::NetworkAcl
      Properties:
         VpcId: vpc-1122334455aabbccd
  InboundRule:
    Type: AWS::EC2::NetworkAclEntry
    Properties:
       NetworkAclId:
         Ref: myNetworkAcl
       Egress: true
       Protocol: 6
       RuleAction: allow
       CidrBlock: 172.16.0.0/24
       PortRange:
         From: 22
         To: "23"
  myLaunchConfig: 
    Type: AWS::AutoScaling::LaunchConfiguration
    Properties:
      LaunchConfigurationName: test-cfg
      InstanceId: !Ref MyEC2Instance
      AssociatePublicIpAddress: true
      SecurityGroups: 
        - !Ref InstanceSecurityGroup
      UserData: test
      BlockDeviceMappings: 
        - DeviceName: /dev/sda1
          Ebs: 
            VolumeSize: '30'
            VolumeType: gp3
            Encrypted: true
        - DeviceName: /dev/sdm
          Ebs: 
            VolumeSize: '100'
            DeleteOnTermination: false
      MetadataOptions:
        HttpTokens: required
        HttpEndpoint: disabled
`,
			expected: ec2.EC2{
				Instances: []ec2.Instance{
					{
						MetadataOptions: ec2.MetadataOptions{
							HttpEndpoint: types.StringDefault("enabled", types.NewTestMetadata()),
							HttpTokens:   types.StringDefault("optional", types.NewTestMetadata()),
						},
						RootBlockDevice: &ec2.BlockDevice{
							Encrypted: types.BoolDefault(true, types.NewTestMetadata()),
						},
						EBSBlockDevices: []*ec2.BlockDevice{
							{
								Encrypted: types.BoolDefault(false, types.NewTestMetadata()),
							},
						},
					},
				},
				Volumes: []ec2.Volume{
					{
						Encryption: ec2.Encryption{
							KMSKeyID: types.StringTest("alias/my_cmk"),
							Enabled:  types.BoolTest(true),
						},
					},
				},
				Subnets: []ec2.Subnet{
					{
						MapPublicIpOnLaunch: types.BoolTest(true),
					},
				},
				SecurityGroups: []ec2.SecurityGroup{
					{
						IsDefault:   types.BoolTest(true),
						Description: types.StringTest("Allow http to client host"),
						VPCID:       types.StringTest("vpc-id"),
						IngressRules: []ec2.SecurityGroupRule{
							{
								Description: types.StringTest("ingress"),
								CIDRs: []types.StringValue{
									types.StringTest("0.0.0.0/0"),
								},
								FromPort: types.IntTest(80),
								ToPort:   types.IntTest(80),
								Protocol: types.StringTest("tcp"),
							},
						},
						EgressRules: []ec2.SecurityGroupRule{
							{
								Description: types.StringTest("egress"),
								CIDRs: []types.StringValue{
									types.StringTest("0.0.0.0/0"),
								},
								FromPort: types.IntTest(80),
								ToPort:   types.IntTest(80),
								Protocol: types.StringTest("-1"),
							},
						},
					},
				},
				NetworkACLs: []ec2.NetworkACL{
					{
						Rules: []ec2.NetworkACLRule{
							{
								Type:     types.StringTest(ec2.TypeEgress),
								Action:   types.StringTest(ec2.ActionAllow),
								Protocol: types.StringTest("6"),
								CIDRs: []types.StringValue{
									types.StringTest("172.16.0.0/24"),
								},
								FromPort: types.IntTest(22),
								ToPort:   types.IntTest(23),
							},
						},
					},
				},
				LaunchConfigurations: []ec2.LaunchConfiguration{
					{
						Name:              types.StringTest("test-cfg"),
						AssociatePublicIP: types.BoolTest(true),
						RootBlockDevice: &ec2.BlockDevice{
							Encrypted: types.BoolTest(true),
						},
						EBSBlockDevices: []*ec2.BlockDevice{
							{
								Encrypted: types.BoolTest(false),
							},
						},
						UserData: types.StringTest("test"),
						MetadataOptions: ec2.MetadataOptions{
							HttpTokens:   types.StringTest("required"),
							HttpEndpoint: types.StringTest("disabled"),
						},
					},
				},
			},
		},
		{
			name: "ec2 instance with launch template, ref to name",
			source: `AWSTemplateFormatVersion: 2010-09-09
Resources:
  MyLaunchTemplate:
    Type: AWS::EC2::LaunchTemplate
    Properties:
        LaunchTemplateName: MyTemplate
        LaunchTemplateData:
          MetadataOptions:
            HttpEndpoint: enabled
            HttpTokens: required
  MyEC2Instance:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: "ami-79fd7eee"
      LaunchTemplate:
        LaunchTemplateName: MyTemplate
`,
			expected: ec2.EC2{
				LaunchTemplates: []ec2.LaunchTemplate{
					{
						Name: types.StringTest("MyTemplate"),
						Instance: ec2.Instance{
							MetadataOptions: ec2.MetadataOptions{
								HttpEndpoint: types.StringTest("enabled"),
								HttpTokens:   types.StringTest("required"),
							},
						},
					},
				},
				Instances: []ec2.Instance{
					{
						MetadataOptions: ec2.MetadataOptions{
							HttpEndpoint: types.StringTest("enabled"),
							HttpTokens:   types.StringTest("required"),
						},
						RootBlockDevice: &ec2.BlockDevice{
							Encrypted: types.BoolTest(false),
						},
					},
				},
			},
		},
		{
			name: "ec2 instance with launch template, ref to id",
			source: `AWSTemplateFormatVersion: 2010-09-09
Resources:
  MyLaunchTemplate:
    Type: AWS::EC2::LaunchTemplate
    Properties:
        LaunchTemplateName: MyTemplate
        LaunchTemplateData:
          MetadataOptions:
            HttpEndpoint: enabled
            HttpTokens: required
  MyEC2Instance:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: "ami-79fd7eee"
      LaunchTemplate:
        LaunchTemplateId: !Ref MyLaunchTemplate
`,
			expected: ec2.EC2{
				LaunchTemplates: []ec2.LaunchTemplate{
					{
						Name: types.StringTest("MyTemplate"),
						Instance: ec2.Instance{
							MetadataOptions: ec2.MetadataOptions{
								HttpEndpoint: types.StringTest("enabled"),
								HttpTokens:   types.StringTest("required"),
							},
						},
					},
				},
				Instances: []ec2.Instance{
					{
						MetadataOptions: ec2.MetadataOptions{
							HttpEndpoint: types.StringTest("enabled"),
							HttpTokens:   types.StringTest("required"),
						},
						RootBlockDevice: &ec2.BlockDevice{
							Encrypted: types.BoolTest(false),
						},
					},
				},
			},
		},
		{
			name: "security group with ingress and egress rules",
			source: `AWSTemplateFormatVersion: 2010-09-09
Resources:
  MySecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupName: MySecurityGroup
      GroupDescription: MySecurityGroup
  InboundRule:
    Type: AWS::EC2::SecurityGroupIngress
    Properties:
      GroupId: !Ref MySecurityGroup
      Description: Inbound
      CidrIp: 0.0.0.0/0
  OutboundRule:
    Type: AWS::EC2::SecurityGroupEgress
    Properties:
      GroupId: !GetAtt MySecurityGroup.GroupId
      Description: Outbound
      CidrIp: 0.0.0.0/0
  RuleWithoutGroup:
    Type: AWS::EC2::SecurityGroupIngress
    Properties:
      CidrIpv6: ::/0
      Description: Inbound
`,
			expected: ec2.EC2{
				SecurityGroups: []ec2.SecurityGroup{
					{
						Description: types.StringTest("MySecurityGroup"),
						IngressRules: []ec2.SecurityGroupRule{
							{
								Description: types.StringTest("Inbound"),
								CIDRs: []types.StringValue{
									types.StringTest("0.0.0.0/0"),
								},
								FromPort: types.IntTest(-1),
								ToPort:   types.IntTest(-1),
							},
						},
						EgressRules: []ec2.SecurityGroupRule{
							{
								Description: types.StringTest("Outbound"),
								CIDRs: []types.StringValue{
									types.StringTest("0.0.0.0/0"),
								},
								FromPort: types.IntTest(-1),
								ToPort:   types.IntTest(-1),
							},
						},
					},
				},
			},
		},
		{
			name: "empty",
			source: `---
AWSTemplateFormatVersion: 2010-09-09
Description: Godd example of excessive ports
Resources: 
  NetworkACL:
    Type: AWS::EC2::NetworkAcl
  Rule:
    Type: AWS::EC2::NetworkAclEntry
    Properties:
      NetworkAclId:
        Ref: NetworkACL`,
			expected: ec2.EC2{
				NetworkACLs: []ec2.NetworkACL{
					{
						Rules: []ec2.NetworkACLRule{
							{
								Action:   types.StringTest("allow"),
								Type:     types.StringTest("ingress"),
								FromPort: types.IntTest(-1),
								ToPort:   types.IntTest(-1),
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testutil.AdaptAndCompare(t, tt.source, tt.expected, Adapt)
		})
	}

}
