package kinesis

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/kinesis"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func Adapt(modules terraform.Modules) kinesis.Kinesis {
	return kinesis.Kinesis{
		Streams: adaptStreams(modules),
	}
}

func adaptStreams(modules terraform.Modules) []kinesis.Stream {
	var streams []kinesis.Stream
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_kinesis_stream") {
			streams = append(streams, adaptStream(resource))
		}
	}
	return streams
}

func adaptStream(resource *terraform.Block) kinesis.Stream {

	stream := kinesis.Stream{
		Metadata: resource.GetMetadata(),
		Encryption: kinesis.Encryption{
			Metadata: resource.GetMetadata(),
			Type:     types.StringDefault("NONE", resource.GetMetadata()),
			KMSKeyID: types.StringDefault("", resource.GetMetadata()),
		},
	}

	encryptionTypeAttr := resource.GetAttribute("encryption_type")
	stream.Encryption.Type = encryptionTypeAttr.AsStringValueOrDefault("NONE", resource)
	KMSKeyIDAttr := resource.GetAttribute("kms_key_id")
	stream.Encryption.KMSKeyID = KMSKeyIDAttr.AsStringValueOrDefault("", resource)
	return stream
}
