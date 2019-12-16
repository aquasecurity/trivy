package cache

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRealCache_Clear(t *testing.T) {
	d, _ := ioutil.TempDir("", "TestRealCache_Clear")
	c := Initialize(d)
	assert.NoError(t, c.Clear())
	_, err := os.Stat(d)
	assert.True(t, os.IsNotExist(err))

	t.Run("sad path, cache dir doesn't exist", func(t *testing.T) {
		c := Initialize(".")
		assert.Equal(t, "failed to remove cache", c.Clear().Error())
	})
}
