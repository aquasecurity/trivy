package aws

import (
	"github.com/aquasecurity/defsec/providers/aws/apigateway"
	"github.com/aquasecurity/defsec/providers/aws/athena"
	"github.com/aquasecurity/defsec/providers/aws/autoscaling"
	"github.com/aquasecurity/defsec/providers/aws/cloudfront"
	"github.com/aquasecurity/defsec/providers/aws/cloudtrail"
	"github.com/aquasecurity/defsec/providers/aws/cloudwatch"
	"github.com/aquasecurity/defsec/providers/aws/codebuild"
	"github.com/aquasecurity/defsec/providers/aws/config"
	"github.com/aquasecurity/defsec/providers/aws/documentdb"
	"github.com/aquasecurity/defsec/providers/aws/dynamodb"
	"github.com/aquasecurity/defsec/providers/aws/ebs"
	"github.com/aquasecurity/defsec/providers/aws/ec2"
	"github.com/aquasecurity/defsec/providers/aws/ecr"
	"github.com/aquasecurity/defsec/providers/aws/ecs"
	"github.com/aquasecurity/defsec/providers/aws/efs"
	"github.com/aquasecurity/defsec/providers/aws/eks"
	"github.com/aquasecurity/defsec/providers/aws/elasticache"
	"github.com/aquasecurity/defsec/providers/aws/elasticsearch"
	"github.com/aquasecurity/defsec/providers/aws/elb"
	"github.com/aquasecurity/defsec/providers/aws/iam"
	"github.com/aquasecurity/defsec/providers/aws/kinesis"
	"github.com/aquasecurity/defsec/providers/aws/kms"
	"github.com/aquasecurity/defsec/providers/aws/lambda"
	"github.com/aquasecurity/defsec/providers/aws/mq"
	"github.com/aquasecurity/defsec/providers/aws/msk"
	"github.com/aquasecurity/defsec/providers/aws/neptune"
	"github.com/aquasecurity/defsec/providers/aws/rds"
	"github.com/aquasecurity/defsec/providers/aws/redshift"
	"github.com/aquasecurity/defsec/providers/aws/s3"
	"github.com/aquasecurity/defsec/providers/aws/sam"
	"github.com/aquasecurity/defsec/providers/aws/sns"
	"github.com/aquasecurity/defsec/providers/aws/sqs"
	"github.com/aquasecurity/defsec/providers/aws/ssm"
	"github.com/aquasecurity/defsec/providers/aws/vpc"
	"github.com/aquasecurity/defsec/providers/aws/workspaces"
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
