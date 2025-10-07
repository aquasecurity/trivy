package kinesis

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/kinesis"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
)

// Adapt adapts a Kinesis instance
func Adapt(cfFile parser.FileContext) kinesis.Kinesis {
	return kinesis.Kinesis{
		Streams: getStreams(cfFile),
	}
}
