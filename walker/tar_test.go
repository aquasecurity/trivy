package walker_test

import (
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/fanal/analyzer"

	"github.com/aquasecurity/fanal/walker"
	"github.com/stretchr/testify/require"
)

func TestWalkLayerTar(t *testing.T) {
	// happy path
	f, err := os.Open("testdata/test.tar")
	require.NoError(t, err)

	opqDirs, whFiles, layerSize, err := walker.WalkLayerTar(f, func(filePath string, info os.FileInfo, opener analyzer.Opener) error {
		if filePath == "baz" {
			b, err := opener()
			require.NoError(t, err)
			assert.Equal(t, "baz\n", string(b))
		} else {
			require.Fail(t, "invalid file", filePath)
		}
		return nil
	})
	assert.Equal(t, []string{"etc/"}, opqDirs)
	assert.Equal(t, int64(8), layerSize)
	assert.Equal(t, []string{"foo/foo"}, whFiles)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	// sad path
	f, err = os.Open("testdata/test.tar")
	require.NoError(t, err)

	_, _, _, err = walker.WalkLayerTar(f, func(filePath string, info os.FileInfo, opener analyzer.Opener) error {
		return errors.New("error")
	})
	require.EqualError(t, err, "failed to analyze file: error")
	require.NoError(t, f.Close())
}
