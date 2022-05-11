package aws

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloudformation/aws/apigateway"
	"github.com/aquasecurity/defsec/internal/adapters/cloudformation/aws/athena"
	"github.com/aquasecurity/defsec/internal/adapters/cloudformation/aws/autoscaling"
	"github.com/aquasecurity/defsec/internal/adapters/cloudformation/aws/cloudfront"
	"github.com/aquasecurity/defsec/internal/adapters/cloudformation/aws/cloudtrail"
	"github.com/aquasecurity/defsec/internal/adapters/cloudformation/aws/cloudwatch"
	"github.com/aquasecurity/defsec/internal/adapters/cloudformation/aws/codebuild"
	"github.com/aquasecurity/defsec/internal/adapters/cloudformation/aws/config"
	"github.com/aquasecurity/defsec/internal/adapters/cloudformation/aws/documentdb"
	"github.com/aquasecurity/defsec/internal/adapters/cloudformation/aws/dynamodb"
	"github.com/aquasecurity/defsec/internal/adapters/cloudformation/aws/ebs"
	"github.com/aquasecurity/defsec/internal/adapters/cloudformation/aws/ec2"
	"github.com/aquasecurity/defsec/internal/adapters/cloudformation/aws/ecr"
	"github.com/aquasecurity/defsec/internal/adapters/cloudformation/aws/ecs"
	"github.com/aquasecurity/defsec/internal/adapters/cloudformation/aws/efs"
	"github.com/aquasecurity/defsec/internal/adapters/cloudformation/aws/eks"
	"github.com/aquasecurity/defsec/internal/adapters/cloudformation/aws/elasticache"
	"github.com/aquasecurity/defsec/internal/adapters/cloudformation/aws/elasticsearch"
	"github.com/aquasecurity/defsec/internal/adapters/cloudformation/aws/elb"
	"github.com/aquasecurity/defsec/internal/adapters/cloudformation/aws/iam"
	"github.com/aquasecurity/defsec/internal/adapters/cloudformation/aws/kinesis"
	"github.com/aquasecurity/defsec/internal/adapters/cloudformation/aws/lambda"
	"github.com/aquasecurity/defsec/internal/adapters/cloudformation/aws/mq"
	"github.com/aquasecurity/defsec/internal/adapters/cloudformation/aws/msk"
	"github.com/aquasecurity/defsec/internal/adapters/cloudformation/aws/neptune"
	"github.com/aquasecurity/defsec/internal/adapters/cloudformation/aws/rds"
	"github.com/aquasecurity/defsec/internal/adapters/cloudformation/aws/redshift"
	"github.com/aquasecurity/defsec/internal/adapters/cloudformation/aws/s3"
	"github.com/aquasecurity/defsec/internal/adapters/cloudformation/aws/sam"
	"github.com/aquasecurity/defsec/internal/adapters/cloudformation/aws/sns"
	"github.com/aquasecurity/defsec/internal/adapters/cloudformation/aws/sqs"
	"github.com/aquasecurity/defsec/internal/adapters/cloudformation/aws/ssm"
	"github.com/aquasecurity/defsec/internal/adapters/cloudformation/aws/vpc"
	"github.com/aquasecurity/defsec/internal/adapters/cloudformation/aws/workspaces"
	"github.com/aquasecurity/defsec/pkg/providers/aws"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) aws.AWS {
	return aws.AWS{
		APIGateway:    apigateway.Adapt(cfFile),
		Athena:        athena.Adapt(cfFile),
		Autoscaling:   autoscaling.Adapt(cfFile),
		Cloudfront:    cloudfront.Adapt(cfFile),
		CloudTrail:    cloudtrail.Adapt(cfFile),
		CloudWatch:    cloudwatch.Adapt(cfFile),
		CodeBuild:     codebuild.Adapt(cfFile),
		Config:        config.Adapt(cfFile),
		DocumentDB:    documentdb.Adapt(cfFile),
		DynamoDB:      dynamodb.Adapt(cfFile),
		EBS:           ebs.Adapt(cfFile),
		EC2:           ec2.Adapt(cfFile),
		ECR:           ecr.Adapt(cfFile),
		ECS:           ecs.Adapt(cfFile),
		EFS:           efs.Adapt(cfFile),
		IAM:           iam.Adapt(cfFile),
		EKS:           eks.Adapt(cfFile),
		ElastiCache:   elasticache.Adapt(cfFile),
		Elasticsearch: elasticsearch.Adapt(cfFile),
		ELB:           elb.Adapt(cfFile),
		MSK:           msk.Adapt(cfFile),
		MQ:            mq.Adapt(cfFile),
		Kinesis:       kinesis.Adapt(cfFile),
		Lambda:        lambda.Adapt(cfFile),
		Neptune:       neptune.Adapt(cfFile),
		RDS:           rds.Adapt(cfFile),
		Redshift:      redshift.Adapt(cfFile),
		S3:            s3.Adapt(cfFile),
		SAM:           sam.Adapt(cfFile),
		SNS:           sns.Adapt(cfFile),
		SQS:           sqs.Adapt(cfFile),
		SSM:           ssm.Adapt(cfFile),
		VPC:           vpc.Adapt(cfFile),
		WorkSpaces:    workspaces.Adapt(cfFile),
	}
}
