package cache

import (
	"bytes"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetAndGetAndClear(t *testing.T) {
	d, _ := ioutil.TempDir("", "TestCacheDir-*")
	f, _ := ioutil.TempFile(d, "foo.bar.baz-*")

	oldCacheDir := cacheDir
	defer func() {
		cacheDir = oldCacheDir
		_ = os.RemoveAll(d)
	}()
	cacheDir = d

	// set
	expectedCacheContents := "foo bar baz"
	var buf bytes.Buffer
	buf.Write([]byte(expectedCacheContents))

	r, err := Set(f.Name(), &buf)
	assert.NoError(t, err)

	b, _ := ioutil.ReadAll(r)
	assert.Equal(t, expectedCacheContents, string(b))

	// get
	actualFile := Get(f.Name())
	actualBytes, _ := ioutil.ReadAll(actualFile)
	assert.Equal(t, expectedCacheContents, string(actualBytes))

	// clear
	assert.NoError(t, Clear())

	// confirm that no cachedir remains
	_, err = os.Stat(d)
	assert.True(t, os.IsNotExist(err))
}
