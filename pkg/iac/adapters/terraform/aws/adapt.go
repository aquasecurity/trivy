package aws

import (
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/aws/apigateway"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/aws/athena"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/aws/cloudfront"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/aws/cloudtrail"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/aws/cloudwatch"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/aws/codebuild"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/aws/config"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/aws/documentdb"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/aws/dynamodb"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/aws/ec2"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/aws/ecr"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/aws/ecs"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/aws/efs"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/aws/eks"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/aws/elasticache"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/aws/elasticsearch"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/aws/elb"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/aws/emr"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/aws/iam"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/aws/kinesis"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/aws/kms"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/aws/lambda"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/aws/mq"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/aws/msk"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/aws/neptune"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/aws/provider"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/aws/rds"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/aws/redshift"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/aws/s3"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/aws/sns"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/aws/sqs"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/aws/ssm"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/aws/workspaces"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

func Adapt(modules terraform.Modules) aws.AWS {
	return aws.AWS{
		Meta: aws.Meta{
			TFProviders: provider.Adapt(modules),
		},
		APIGateway:    apigateway.Adapt(modules),
		Athena:        athena.Adapt(modules),
		Cloudfront:    cloudfront.Adapt(modules),
		CloudTrail:    cloudtrail.Adapt(modules),
		CloudWatch:    cloudwatch.Adapt(modules),
		CodeBuild:     codebuild.Adapt(modules),
		Config:        config.Adapt(modules),
		DocumentDB:    documentdb.Adapt(modules),
		DynamoDB:      dynamodb.Adapt(modules),
		EC2:           ec2.Adapt(modules),
		ECR:           ecr.Adapt(modules),
		ECS:           ecs.Adapt(modules),
		EFS:           efs.Adapt(modules),
		EKS:           eks.Adapt(modules),
		ElastiCache:   elasticache.Adapt(modules),
		Elasticsearch: elasticsearch.Adapt(modules),
		ELB:           elb.Adapt(modules),
		EMR:           emr.Adapt(modules),
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
		WorkSpaces:    workspaces.Adapt(modules),
	}
}
