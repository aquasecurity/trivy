package walker

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_isIgnore(t *testing.T) {
	for _, fp := range ignoreDirs {
		assert.True(t, isIgnored(fp))
	}

	for _, fp := range ignoreSystemDirs {
		assert.True(t, isIgnored(fp))
	}

	for _, fp := range []string{"foo", "foo/bar"} {
		assert.False(t, isIgnored(fp))
	}
}
