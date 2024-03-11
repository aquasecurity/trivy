package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Reference(t *testing.T) {
	assert.Equal(t, "test-reference", Reference("test"))
	assert.Equal(t, "123-reference", Reference(123))
}
