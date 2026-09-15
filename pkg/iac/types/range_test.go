package types

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const encodedRange = `{"filename":"main.tf","startLine":2,"endLine":4,"sourcePrefix":"prefix","fsKey":"fs-key","isLogicalSource":true}`

func Test_RangeJSON(t *testing.T) {
	rng := newRange("main.tf", 2, 4, "prefix", "fs-key", nil, true)

	t.Run("marshal", func(t *testing.T) {
		data, err := json.Marshal(rng)
		require.NoError(t, err)
		assert.JSONEq(t, encodedRange, string(data))
	})

	t.Run("unmarshal", func(t *testing.T) {
		var restored Range
		require.NoError(t, json.Unmarshal([]byte(encodedRange), &restored))
		assert.Equal(t, rng, restored)
	})
}
