package cyclonedx

import (
	"bytes"
)

func FuzzUnmarshal(data []byte) int {
	r := bytes.NewReader(data)
	unmarshaler := NewJSONUnmarshaler()
	_, _ = unmarshaler.Unmarshal(r)
	return 1
}
