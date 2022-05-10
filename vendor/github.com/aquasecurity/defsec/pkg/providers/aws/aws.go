package aws

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/apigateway"
	"github.com/aquasecurity/defsec/pkg/providers/aws/athena"
	"github.com/aquasecurity/defsec/pkg/providers/aws/autoscaling"
	"github.com/aquasecurity/defsec/pkg/providers/aws/cloudfront"
	"github.com/aquasecurity/defsec/pkg/providers/aws/cloudtrail"
	"github.com/aquasecurity/defsec/pkg/providers/aws/cloudwatch"
	"github.com/aquasecurity/defsec/pkg/providers/aws/codebuild"
	"github.com/aquasecurity/defsec/pkg/providers/aws/config"
	"github.com/aquasecurity/defsec/pkg/providers/aws/documentdb"
	"github.com/aquasecurity/defsec/pkg/providers/aws/dynamodb"
	"github.com/aquasecurity/defsec/pkg/providers/aws/ebs"
	"github.com/aquasecurity/defsec/pkg/providers/aws/ec2"
	"github.com/aquasecurity/defsec/pkg/providers/aws/ecr"
	"github.com/aquasecurity/defsec/pkg/providers/aws/ecs"
	"github.com/aquasecurity/defsec/pkg/providers/aws/efs"
	"github.com/aquasecurity/defsec/pkg/providers/aws/eks"
	"github.com/aquasecurity/defsec/pkg/providers/aws/elasticache"
	"github.com/aquasecurity/defsec/pkg/providers/aws/elasticsearch"
	"github.com/aquasecurity/defsec/pkg/providers/aws/elb"
	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	"github.com/aquasecurity/defsec/pkg/providers/aws/kinesis"
	"github.com/aquasecurity/defsec/pkg/providers/aws/kms"
	"github.com/aquasecurity/defsec/pkg/providers/aws/lambda"
	"github.com/aquasecurity/defsec/pkg/providers/aws/mq"
	"github.com/aquasecurity/defsec/pkg/providers/aws/msk"
	"github.com/aquasecurity/defsec/pkg/providers/aws/neptune"
	"github.com/aquasecurity/defsec/pkg/providers/aws/rds"
	"github.com/aquasecurity/defsec/pkg/providers/aws/redshift"
	"github.com/aquasecurity/defsec/pkg/providers/aws/s3"
	"github.com/aquasecurity/defsec/pkg/providers/aws/sam"
	"github.com/aquasecurity/defsec/pkg/providers/aws/sns"
	"github.com/aquasecurity/defsec/pkg/providers/aws/sqs"
	"github.com/aquasecurity/defsec/pkg/providers/aws/ssm"
	"github.com/aquasecurity/defsec/pkg/providers/aws/vpc"
	"github.com/aquasecurity/defsec/pkg/providers/aws/workspaces"
)

type AWS struct {
	APIGateway    apigateway.APIGateway
	Athena        athena.Athena
	Autoscaling   autoscaling.Autoscaling
	Cloudfront    cloudfront.Cloudfront
	CloudTrail    cloudtrail.CloudTrail
	CloudWatch    cloudwatch.CloudWatch
	CodeBuild     codebuild.CodeBuild
	Config        config.Config
	DocumentDB    documentdb.DocumentDB
	DynamoDB      dynamodb.DynamoDB
	EBS           ebs.EBS
	EC2           ec2.EC2
	ECR           ecr.ECR
	ECS           ecs.ECS
	EFS           efs.EFS
	EKS           eks.EKS
	ElastiCache   elasticache.ElastiCache
	Elasticsearch elasticsearch.Elasticsearch
	ELB           elb.ELB
	IAM           iam.IAM
	Kinesis       kinesis.Kinesis
	KMS           kms.KMS
	Lambda        lambda.Lambda
	MQ            mq.MQ
	MSK           msk.MSK
	Neptune       neptune.Neptune
	RDS           rds.RDS
	Redshift      redshift.Redshift
	SAM           sam.SAM
	S3            s3.S3
	SNS           sns.SNS
	SQS           sqs.SQS
	SSM           ssm.SSM
	VPC           vpc.VPC
	WorkSpaces    workspaces.WorkSpaces
}
