package kinesis

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/kinesis"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result kinesis.Kinesis) {

	result.Streams = getStreams(cfFile)
	return result
}
