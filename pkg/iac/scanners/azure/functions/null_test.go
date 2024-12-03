package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Null(t *testing.T) {

	assert.Nil(t, Null())
}
