package iam

import (
	"testing"

	"github.com/liamg/iamgo"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/iam"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func TestAdapt(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected iam.IAM
	}{
		{
			name: "complete",
			source: `AWSTemplateFormatVersion: '2010-09-09'
Resources:
  myIAMPolicy:
    Type: 'AWS::IAM::Policy'
    Properties:
      PolicyName: TestPolicy
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Action:
              - 'cloudformation:Describe*'
            Resource: '*'
      Groups:
        - !Ref MyGroup
      Users:
        - !Ref PublishUser
      Roles:
        - !Ref MyRole
  MyGroup:
    Type: AWS::IAM::Group
    Properties:
      GroupName: TestGroup
      Policies:
        - PolicyName: TestGroupPolicy
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Resource: arn:*:cloudfront::*:distribution/*
                Action:
                  - cloudfront:CreateDistribution
  MyUser:
    Type: AWS::IAM::User
    Properties:
      UserName: TestUser
      Policies:
        - PolicyName: TestUserPolicy
          PolicyDocument:
            Statement:
            - Action: 's3:*'
              Effect: Allow
              Resource: 
              - 'arn:aws:s3:::testbucket'
  MyRole:
    Type: 'AWS::IAM::Role'
    Properties:
      RoleName: TestRole
      Policies:
        - PolicyName: TestRolePolicy
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action:
                  - 'sts:AssumeRole'
  AccessKey:
    Type: AWS::IAM::AccessKey
    Properties:
      UserName: !Ref MyUser
      Status: Active
`,
			expected: iam.IAM{
				Policies: []iam.Policy{
					{
						Name: types.StringTest("TestPolicy"),
						Document: func() iam.Document {
							return iam.Document{
								Parsed: iamgo.NewPolicyBuilder().
									WithVersion("2012-10-17").
									WithStatement(
										iamgo.NewStatementBuilder().
											WithEffect("Allow").
											WithActions([]string{"cloudformation:Describe*"}).
											WithResources([]string{"*"}).
											Build(),
									).
									Build(),
							}
						}(),
					},
				},
				Users: []iam.User{
					{
						Name: types.StringTest("TestUser"),
						Policies: []iam.Policy{
							{
								Name: types.StringTest("TestUserPolicy"),
								Document: func() iam.Document {
									return iam.Document{
										Parsed: iamgo.NewPolicyBuilder().
											WithStatement(
												iamgo.NewStatementBuilder().
													WithEffect("Allow").
													WithActions([]string{"s3:*"}).
													WithResources([]string{"arn:aws:s3:::testbucket"}).
													Build(),
											).
											Build(),
									}
								}(),
							},
						},
					},
				},
				Groups: []iam.Group{
					{
						Name: types.StringTest("TestGroup"),
						Policies: []iam.Policy{
							{
								Name: types.StringTest("TestGroupPolicy"),
								Document: func() iam.Document {
									return iam.Document{
										Parsed: iamgo.NewPolicyBuilder().
											WithVersion("2012-10-17").
											WithStatement(
												iamgo.NewStatementBuilder().
													WithEffect("Allow").
													WithActions([]string{"cloudfront:CreateDistribution"}).
													WithResources([]string{"arn:*:cloudfront::*:distribution/*"}).
													Build(),
											).
											Build(),
									}
								}(),
							},
						},
					},
				},
				Roles: []iam.Role{
					{
						Name: types.StringTest("TestRole"),
						Policies: []iam.Policy{
							{
								Name: types.StringTest("TestRolePolicy"),
								Document: func() iam.Document {
									return iam.Document{
										Parsed: iamgo.NewPolicyBuilder().
											WithVersion("2012-10-17").
											WithStatement(
												iamgo.NewStatementBuilder().
													WithEffect("Allow").
													WithActions([]string{"sts:AssumeRole"}).
													Build(),
											).
											Build(),
									}
								}(),
							},
						},
					},
				},
			},
		},
		{
			name: "empty",
			source: `AWSTemplateFormatVersion: 2010-09-09
Resources:

  `,
			expected: iam.IAM{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testutil.AdaptAndCompare(t, tt.source, tt.expected, Adapt)
		})
	}
}
