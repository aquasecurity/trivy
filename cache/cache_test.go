package cache

import (
	"bytes"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetAndGetAndClear(t *testing.T) {
	tempCacheDir, _ := ioutil.TempDir("", "TestCacheDir-*")
	f, _ := ioutil.TempFile(tempCacheDir, "foo.bar.baz-*")

	c := Initialize(tempCacheDir)

	// set
	expectedCacheContents := "foo bar baz"
	var buf bytes.Buffer
	buf.Write([]byte(expectedCacheContents))

	r, err := c.Set(f.Name(), &buf)
	assert.NoError(t, err)

	b, _ := ioutil.ReadAll(r)
	assert.Equal(t, expectedCacheContents, string(b))

	// get
	actualFile := c.Get(f.Name())
	actualBytes, _ := ioutil.ReadAll(actualFile)
	assert.Equal(t, expectedCacheContents, string(actualBytes))

	// clear
	assert.NoError(t, c.Clear())

	// confirm that no cachedir remains
	_, err = os.Stat(tempCacheDir)
	assert.True(t, os.IsNotExist(err))
}
