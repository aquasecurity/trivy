package ec2

import (
	"context"
	"testing"

	"github.com/aquasecurity/trivy/pkg/providers/aws/ec2"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/scanners/cloudformation/parser"
	"github.com/aquasecurity/trivy/test/testutil"
)

func TestAdapt(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected ec2.EC2
	}{
		{
			name: "ec2 instance",
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
`,
			expected: ec2.EC2{
				Instances: []ec2.Instance{
					{
						Metadata: types.NewTestMisconfigMetadata(),
						MetadataOptions: ec2.MetadataOptions{
							HttpEndpoint: types.StringDefault("enabled", types.NewTestMisconfigMetadata()),
							HttpTokens:   types.StringDefault("optional", types.NewTestMisconfigMetadata()),
						},
						RootBlockDevice: &ec2.BlockDevice{
							Metadata:  types.NewTestMisconfigMetadata(),
							Encrypted: types.BoolDefault(true, types.NewTestMisconfigMetadata()),
						},
						EBSBlockDevices: []*ec2.BlockDevice{
							{
								Metadata:  types.NewTestMisconfigMetadata(),
								Encrypted: types.BoolDefault(false, types.NewTestMisconfigMetadata()),
							},
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
						Metadata: types.NewTestMisconfigMetadata(),
						Name:     types.String("MyTemplate", types.NewTestMisconfigMetadata()),
						Instance: ec2.Instance{
							Metadata: types.NewTestMisconfigMetadata(),
							MetadataOptions: ec2.MetadataOptions{
								HttpEndpoint: types.String("enabled", types.NewTestMisconfigMetadata()),
								HttpTokens:   types.String("required", types.NewTestMisconfigMetadata()),
							},
						},
					},
				},
				Instances: []ec2.Instance{
					{
						Metadata: types.NewTestMisconfigMetadata(),
						MetadataOptions: ec2.MetadataOptions{
							HttpEndpoint: types.String("enabled", types.NewTestMisconfigMetadata()),
							HttpTokens:   types.String("required", types.NewTestMisconfigMetadata()),
						},
						RootBlockDevice: &ec2.BlockDevice{
							Metadata:  types.NewTestMisconfigMetadata(),
							Encrypted: types.Bool(false, types.NewTestMisconfigMetadata()),
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
						Metadata: types.NewTestMisconfigMetadata(),
						Name:     types.String("MyTemplate", types.NewTestMisconfigMetadata()),
						Instance: ec2.Instance{
							Metadata: types.NewTestMisconfigMetadata(),
							MetadataOptions: ec2.MetadataOptions{
								HttpEndpoint: types.String("enabled", types.NewTestMisconfigMetadata()),
								HttpTokens:   types.String("required", types.NewTestMisconfigMetadata()),
							},
						},
					},
				},
				Instances: []ec2.Instance{
					{
						Metadata: types.NewTestMisconfigMetadata(),
						MetadataOptions: ec2.MetadataOptions{
							HttpEndpoint: types.String("enabled", types.NewTestMisconfigMetadata()),
							HttpTokens:   types.String("required", types.NewTestMisconfigMetadata()),
						},
						RootBlockDevice: &ec2.BlockDevice{
							Metadata:  types.NewTestMisconfigMetadata(),
							Encrypted: types.Bool(false, types.NewTestMisconfigMetadata()),
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			fsys := testutil.CreateFS(t, map[string]string{
				"main.yaml": tt.source,
			})

			fctx, err := parser.New().ParseFile(context.TODO(), fsys, "main.yaml")
			require.NoError(t, err)

			adapted := Adapt(*fctx)
			testutil.AssertDefsecEqual(t, tt.expected, adapted)
		})
	}

}
