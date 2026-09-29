package s3

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/s3"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

func Adapt(modules terraform.Modules) s3.S3 {

	a := &adapter{
		modules:   modules,
		bucketMap: make(map[string]*s3.Bucket),
	}

	return s3.S3{
		Buckets: a.adaptBuckets(),
	}
}
