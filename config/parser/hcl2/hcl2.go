package hcl2

import (
	"encoding/json"

	"github.com/tmccombs/hcl2json/convert"
	"golang.org/x/xerrors"
)

func Unmarshal(b []byte, v interface{}) error {
	hclBytes, err := convert.Bytes(b, "", convert.Options{})
	if err != nil {
		return xerrors.Errorf("convert hcl2 to bytes: %w", err)
	}

	if err = json.Unmarshal(hclBytes, v); err != nil {
		return xerrors.Errorf("unmarshal hcl2: %w", err)
	}

	return nil
}
