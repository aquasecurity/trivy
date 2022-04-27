package iamgo

import "github.com/liamg/jfather"

func Parse(policy []byte) (*Document, error) {
	var doc Document
	if err := jfather.Unmarshal(policy, &doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

func ParseString(policy string) (*Document, error) {
	return Parse([]byte(policy))
}
