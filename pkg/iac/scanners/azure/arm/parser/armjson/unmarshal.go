package armjson

import (
	"bytes"
	"io"

	"github.com/aquasecurity/trivy/pkg/iac/types"
)

type Unmarshaller interface {
	UnmarshalJSONWithMetadata(node Node) error
}

type MetadataReceiver interface {
	SetMetadata(m *types.Metadata)
}

func Unmarshal(data []byte, target any, metadata *types.Metadata) error {
	node, err := newParser(NewPeekReader(bytes.NewReader(data)), Position{1, 1}).parse(metadata)
	if err != nil {
		return err
	}
	if err := node.Decode(target); err != nil {
		return err
	}

	return nil
}

func UnmarshalFromReader(r io.ReadSeeker, target any, metadata *types.Metadata) error {
	node, err := newParser(NewPeekReader(r), Position{1, 1}).parse(metadata)
	if err != nil {
		return err
	}
	if err := node.Decode(target); err != nil {
		return err
	}

	return nil
}
