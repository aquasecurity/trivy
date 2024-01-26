package s3

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/s3"
	"github.com/aquasecurity/trivy/pkg/scanners/cloudformation/parser"
)

// Adapt adapts an S3 instance
func Adapt(cfFile parser.FileContext) s3.S3 {
	return s3.S3{
		Buckets: getBuckets(cfFile),
	}
}
