package licensing

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// All map keys must be standardized to be matched
// (uppercase, no common suffixes, standardized version, etc.)
func TestMap(t *testing.T) {
	for key := range mapping {
		t.Run(key, func(t *testing.T) {
			standardized := standardizeKeyAndSuffix(key)
			assert.Equal(t, standardized.License, key)
		})
	}
}
