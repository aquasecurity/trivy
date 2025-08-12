package s3

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/s3"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/parser"
)

func Adapt(tasks parser.ResolvedTasks) s3.S3 {
	a := &adapter{
		tasks:     tasks,
		bucketMap: make(map[string]*s3.Bucket),
	}

	return s3.S3{
		Buckets: a.adaptBuckets(),
	}
}
