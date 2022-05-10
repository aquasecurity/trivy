package s3

import "github.com/aquasecurity/defsec/parsers/types"

type S3 struct {
	types.Metadata
	Buckets []Bucket
}
