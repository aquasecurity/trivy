package aws

import (
	"github.com/aquasecurity/trivy/pkg/providers/aws/accessanalyzer"
	"github.com/aquasecurity/trivy/pkg/providers/aws/apigateway"
	"github.com/aquasecurity/trivy/pkg/providers/aws/athena"
	"github.com/aquasecurity/trivy/pkg/providers/aws/cloudfront"
	"github.com/aquasecurity/trivy/pkg/providers/aws/cloudtrail"
	"github.com/aquasecurity/trivy/pkg/providers/aws/cloudwatch"
	"github.com/aquasecurity/trivy/pkg/providers/aws/codebuild"
	"github.com/aquasecurity/trivy/pkg/providers/aws/config"
	"github.com/aquasecurity/trivy/pkg/providers/aws/documentdb"
	"github.com/aquasecurity/trivy/pkg/providers/aws/dynamodb"
	"github.com/aquasecurity/trivy/pkg/providers/aws/ec2"
	"github.com/aquasecurity/trivy/pkg/providers/aws/ecr"
	"github.com/aquasecurity/trivy/pkg/providers/aws/ecs"
	"github.com/aquasecurity/trivy/pkg/providers/aws/efs"
	"github.com/aquasecurity/trivy/pkg/providers/aws/eks"
	"github.com/aquasecurity/trivy/pkg/providers/aws/elasticache"
	"github.com/aquasecurity/trivy/pkg/providers/aws/elasticsearch"
	"github.com/aquasecurity/trivy/pkg/providers/aws/elb"
	"github.com/aquasecurity/trivy/pkg/providers/aws/emr"
	"github.com/aquasecurity/trivy/pkg/providers/aws/iam"
	"github.com/aquasecurity/trivy/pkg/providers/aws/kinesis"
	"github.com/aquasecurity/trivy/pkg/providers/aws/kms"
	"github.com/aquasecurity/trivy/pkg/providers/aws/lambda"
	"github.com/aquasecurity/trivy/pkg/providers/aws/mq"
	"github.com/aquasecurity/trivy/pkg/providers/aws/msk"
	"github.com/aquasecurity/trivy/pkg/providers/aws/neptune"
	"github.com/aquasecurity/trivy/pkg/providers/aws/rds"
	"github.com/aquasecurity/trivy/pkg/providers/aws/redshift"
	"github.com/aquasecurity/trivy/pkg/providers/aws/s3"
	"github.com/aquasecurity/trivy/pkg/providers/aws/sam"
	"github.com/aquasecurity/trivy/pkg/providers/aws/sns"
	"github.com/aquasecurity/trivy/pkg/providers/aws/sqs"
	"github.com/aquasecurity/trivy/pkg/providers/aws/ssm"
	"github.com/aquasecurity/trivy/pkg/providers/aws/workspaces"
)

type AWS struct {
	Meta           Meta
	AccessAnalyzer accessanalyzer.AccessAnalyzer
	APIGateway     apigateway.APIGateway
	Athena         athena.Athena
	Cloudfront     cloudfront.Cloudfront
	CloudTrail     cloudtrail.CloudTrail
	CloudWatch     cloudwatch.CloudWatch
	CodeBuild      codebuild.CodeBuild
	Config         config.Config
	DocumentDB     documentdb.DocumentDB
	DynamoDB       dynamodb.DynamoDB
	EC2            ec2.EC2
	ECR            ecr.ECR
	ECS            ecs.ECS
	EFS            efs.EFS
	EKS            eks.EKS
	ElastiCache    elasticache.ElastiCache
	Elasticsearch  elasticsearch.Elasticsearch
	ELB            elb.ELB
	EMR            emr.EMR
	IAM            iam.IAM
	Kinesis        kinesis.Kinesis
	KMS            kms.KMS
	Lambda         lambda.Lambda
	MQ             mq.MQ
	MSK            msk.MSK
	Neptune        neptune.Neptune
	RDS            rds.RDS
	Redshift       redshift.Redshift
	SAM            sam.SAM
	S3             s3.S3
	SNS            sns.SNS
	SQS            sqs.SQS
	SSM            ssm.SSM
	WorkSpaces     workspaces.WorkSpaces
}

type Meta struct {
	TFProviders []TerraformProvider
}
