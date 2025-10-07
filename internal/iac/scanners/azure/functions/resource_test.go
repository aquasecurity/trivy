package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_ResourceID(t *testing.T) {
	assert.Equal(t, "/test1/test2", ResourceID("test1", "test2"))
	assert.Equal(t, "/test1/123", ResourceID("test1", 123))
}
