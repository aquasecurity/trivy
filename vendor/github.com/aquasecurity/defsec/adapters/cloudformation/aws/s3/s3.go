package s3

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/providers/aws/s3"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result s3.S3) {

	result.Buckets = getBuckets(cfFile)
	return result
}
