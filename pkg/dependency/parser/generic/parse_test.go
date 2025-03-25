package generic

import (
	"testing"
)

func TestNewParser(t *testing.T) {
	p := NewParser()
	if p == nil {
		t.Error("NewParser() returned nil")
	}
}
