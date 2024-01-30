package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_resolve_sub_value(t *testing.T) {
	source := `---
Resources:
  TestInstance:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: "ami-79fd7eee"
      KeyName: "testkey"
      UserData:
        !Sub |
          #!/bin/bash -xe
          yum update -y aws-cfn-bootstrap
          /opt/aws/bin/cfn-init -v --stack ${AWS::StackName} --resource LaunchConfig --configsets wordpress_install --region ${AWS::Region}
          /opt/aws/bin/cfn-signal -e $? --stack ${AWS::StackName} --resource WebServerGroup --region ${AWS::Region}
`
	ctx := createTestFileContext(t, source)
	require.NotNil(t, ctx)

	testRes := ctx.GetResourceByLogicalID("TestInstance")
	require.NotNil(t, testRes)

	userDataProp := testRes.GetProperty("UserData")
	require.NotNil(t, userDataProp)

	assert.Equal(t, "#!/bin/bash -xe\nyum update -y aws-cfn-bootstrap\n/opt/aws/bin/cfn-init -v --stack cfsec-test-stack --resource LaunchConfig --configsets wordpress_install --region eu-west-1\n/opt/aws/bin/cfn-signal -e $? --stack cfsec-test-stack --resource WebServerGroup --region eu-west-1\n", userDataProp.AsString())
}

func Test_resolve_sub_value_with_base64(t *testing.T) {

	source := `---
Resources:
  TestInstance:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: "ami-79fd7eee"
      KeyName: "testkey"
      UserData:
        Fn::Base64:
          !Sub |
            #!/bin/bash -xe
            yum update -y aws-cfn-bootstrap
            /opt/aws/bin/cfn-init -v --stack ${AWS::StackName} --resource LaunchConfig --configsets wordpress_install --region ${AWS::Region}
            /opt/aws/bin/cfn-signal -e $? --stack ${AWS::StackName} --resource WebServerGroup --region ${AWS::Region}`
	ctx := createTestFileContext(t, source)
	require.NotNil(t, ctx)

	testRes := ctx.GetResourceByLogicalID("TestInstance")
	require.NotNil(t, testRes)

	userDataProp := testRes.GetProperty("UserData")
	require.NotNil(t, userDataProp)

	assert.Equal(t, "IyEvYmluL2Jhc2ggLXhlCnl1bSB1cGRhdGUgLXkgYXdzLWNmbi1ib290c3RyYXAKL29wdC9hd3MvYmluL2Nmbi1pbml0IC12IC0tc3RhY2sgY2ZzZWMtdGVzdC1zdGFjayAtLXJlc291cmNlIExhdW5jaENvbmZpZyAtLWNvbmZpZ3NldHMgd29yZHByZXNzX2luc3RhbGwgLS1yZWdpb24gZXUtd2VzdC0xCi9vcHQvYXdzL2Jpbi9jZm4tc2lnbmFsIC1lICQ/IC0tc3RhY2sgY2ZzZWMtdGVzdC1zdGFjayAtLXJlc291cmNlIFdlYlNlcnZlckdyb3VwIC0tcmVnaW9uIGV1LXdlc3QtMQ==", userDataProp.AsString())
}

func Test_resolve_sub_value_with_map(t *testing.T) {

	source := `---
Parameters:
  RootDomainName:
    Type: String
    Default: somedomain.com
Resources:
  TestDistribution:
    Type: AWS::CloudFront::Distribution
    Properties:
      DistributionConfig:
        DefaultCacheBehavior:
          TargetOriginId: target
          ViewerProtocolPolicy: https-only
        Enabled: true
        Origins:
          - DomainName: 
              !Sub
              - www.${Domain}
              - { Domain: !Ref RootDomainName }
            Id: somedomain1
    

`
	ctx := createTestFileContext(t, source)
	require.NotNil(t, ctx)

	testRes := ctx.GetResourceByLogicalID("TestDistribution")
	require.NotNil(t, testRes)

	originsList := testRes.GetProperty("DistributionConfig.Origins")

	domainNameProp := originsList.AsList()[0].GetProperty("DomainName")
	require.NotNil(t, domainNameProp)

	assert.Equal(t, "www.somedomain.com", domainNameProp.AsString())

}
