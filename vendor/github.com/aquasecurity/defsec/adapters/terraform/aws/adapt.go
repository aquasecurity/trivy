package aws

import (
	"github.com/aquasecurity/defsec/adapters/terraform/aws/apigateway"
	"github.com/aquasecurity/defsec/adapters/terraform/aws/athena"
	"github.com/aquasecurity/defsec/adapters/terraform/aws/autoscaling"
	"github.com/aquasecurity/defsec/adapters/terraform/aws/cloudfront"
	"github.com/aquasecurity/defsec/adapters/terraform/aws/cloudtrail"
	"github.com/aquasecurity/defsec/adapters/terraform/aws/cloudwatch"
	"github.com/aquasecurity/defsec/adapters/terraform/aws/codebuild"
	"github.com/aquasecurity/defsec/adapters/terraform/aws/config"
	"github.com/aquasecurity/defsec/adapters/terraform/aws/documentdb"
	"github.com/aquasecurity/defsec/adapters/terraform/aws/dynamodb"
	"github.com/aquasecurity/defsec/adapters/terraform/aws/ebs"
	"github.com/aquasecurity/defsec/adapters/terraform/aws/ec2"
	"github.com/aquasecurity/defsec/adapters/terraform/aws/ecr"
	"github.com/aquasecurity/defsec/adapters/terraform/aws/ecs"
	"github.com/aquasecurity/defsec/adapters/terraform/aws/efs"
	"github.com/aquasecurity/defsec/adapters/terraform/aws/eks"
	"github.com/aquasecurity/defsec/adapters/terraform/aws/elasticache"
	"github.com/aquasecurity/defsec/adapters/terraform/aws/elasticsearch"
	"github.com/aquasecurity/defsec/adapters/terraform/aws/elb"
	"github.com/aquasecurity/defsec/adapters/terraform/aws/iam"
	"github.com/aquasecurity/defsec/adapters/terraform/aws/kinesis"
	"github.com/aquasecurity/defsec/adapters/terraform/aws/kms"
	"github.com/aquasecurity/defsec/adapters/terraform/aws/lambda"
	"github.com/aquasecurity/defsec/adapters/terraform/aws/mq"
	"github.com/aquasecurity/defsec/adapters/terraform/aws/msk"
	"github.com/aquasecurity/defsec/adapters/terraform/aws/neptune"
	"github.com/aquasecurity/defsec/adapters/terraform/aws/rds"
	"github.com/aquasecurity/defsec/adapters/terraform/aws/redshift"
	"github.com/aquasecurity/defsec/adapters/terraform/aws/s3"
	"github.com/aquasecurity/defsec/adapters/terraform/aws/sns"
	"github.com/aquasecurity/defsec/adapters/terraform/aws/sqs"
	"github.com/aquasecurity/defsec/adapters/terraform/aws/ssm"
	"github.com/aquasecurity/defsec/adapters/terraform/aws/vpc"
	"github.com/aquasecurity/defsec/adapters/terraform/aws/workspaces"
	"github.com/aquasecurity/defsec/parsers/terraform"
	"github.com/aquasecurity/defsec/providers/aws"
)

func Adapt(modules terraform.Modules) aws.AWS {
	return aws.AWS{
		APIGateway:    apigateway.Adapt(modules),
		Athena:        athena.Adapt(modules),
		Autoscaling:   autoscaling.Adapt(modules),
		Cloudfront:    cloudfront.Adapt(modules),
		CloudTrail:    cloudtrail.Adapt(modules),
		CloudWatch:    cloudwatch.Adapt(modules),
		CodeBuild:     codebuild.Adapt(modules),
		Config:        config.Adapt(modules),
		DocumentDB:    documentdb.Adapt(modules),
		DynamoDB:      dynamodb.Adapt(modules),
		EBS:           ebs.Adapt(modules),
		EC2:           ec2.Adapt(modules),
		ECR:           ecr.Adapt(modules),
		ECS:           ecs.Adapt(modules),
		EFS:           efs.Adapt(modules),
		EKS:           eks.Adapt(modules),
		ElastiCache:   elasticache.Adapt(modules),
		Elasticsearch: elasticsearch.Adapt(modules),
		ELB:           elb.Adapt(modules),
		IAM:           iam.Adapt(modules),
		Kinesis:       kinesis.Adapt(modules),
		KMS:           kms.Adapt(modules),
		Lambda:        lambda.Adapt(modules),
		MQ:            mq.Adapt(modules),
		MSK:           msk.Adapt(modules),
		Neptune:       neptune.Adapt(modules),
		RDS:           rds.Adapt(modules),
		Redshift:      redshift.Adapt(modules),
		S3:            s3.Adapt(modules),
		SNS:           sns.Adapt(modules),
		SQS:           sqs.Adapt(modules),
		SSM:           ssm.Adapt(modules),
		VPC:           vpc.Adapt(modules),
		WorkSpaces:    workspaces.Adapt(modules),
	}
}
