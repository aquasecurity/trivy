package cache

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRealCache_Clear(t *testing.T) {
	d, _ := ioutil.TempDir("", "TestRealCache_Clear")
	defer os.RemoveAll(d)
	c, err := New(d)
	assert.NoError(t, err)
	assert.NoError(t, c.Clear())
	_, err = os.Stat(filepath.Join(d, "fanal"))
	assert.True(t, os.IsNotExist(err))
}
