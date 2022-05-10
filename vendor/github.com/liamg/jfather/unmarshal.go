package jfather

import "bytes"

type Unmarshaller interface {
	UnmarshalJSONWithMetadata(node Node) error
}

func Unmarshal(data []byte, target interface{}) error {
	node, err := newParser(NewPeekReader(bytes.NewReader(data)), Position{1, 1}).parse()
	if err != nil {
		return err
	}
	return node.Decode(target)
}
