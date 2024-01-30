package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParsingDoubleComment(t *testing.T) {
	ignores := parseIgnoresFromLine("## tfsec:ignore:abc")
	assert.Equal(t, 1, len(ignores))
	assert.Truef(t, ignores[0].Block, "Expected ignore to be a block")
}
