package aws

import (
	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/aws/apigateway"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/aws/athena"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/aws/cloudfront"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/aws/cloudtrail"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/aws/cloudwatch"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/aws/codebuild"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/aws/config"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/aws/documentdb"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/aws/dynamodb"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/aws/ec2"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/aws/ecr"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/aws/ecs"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/aws/efs"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/aws/eks"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/aws/elasticache"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/aws/elasticsearch"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/aws/elb"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/aws/iam"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/aws/kinesis"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/aws/lambda"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/aws/mq"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/aws/msk"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/aws/neptune"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/aws/rds"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/aws/redshift"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/aws/s3"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/aws/sam"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/aws/sns"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/aws/sqs"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/aws/ssm"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/aws/workspaces"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
)

// Adapt adapts a Cloudformation AWS instance
func Adapt(cfFile parser.FileContext) aws.AWS {
	return aws.AWS{
		APIGateway:    apigateway.Adapt(cfFile),
		Athena:        athena.Adapt(cfFile),
		Cloudfront:    cloudfront.Adapt(cfFile),
		CloudTrail:    cloudtrail.Adapt(cfFile),
		CloudWatch:    cloudwatch.Adapt(cfFile),
		CodeBuild:     codebuild.Adapt(cfFile),
		Config:        config.Adapt(cfFile),
		DocumentDB:    documentdb.Adapt(cfFile),
		DynamoDB:      dynamodb.Adapt(cfFile),
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
		WorkSpaces:    workspaces.Adapt(cfFile),
	}
}
