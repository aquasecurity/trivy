package ansible

import (
	"github.com/aquasecurity/trivy/pkg/iac/adapters/ansible/aws/s3"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/parser"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

func Adapt(tasks parser.ResolvedTasks) state.State {
	return state.State{
		AWS: aws.AWS{
			S3: s3.Adapt(tasks),
			// TODO(simar): Add other AWS services
		},
	}
}
