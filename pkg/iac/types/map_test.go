package types

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_MapJSON(t *testing.T) {
	val := Map(map[string]string{
		"yeah":  "it",
		"seems": "to",
		"work":  "fine",
	}, NewMetadata(NewRange("main.tf", 123, 123, "", nil), ""))
	data, err := json.Marshal(val)
	require.NoError(t, err)

	var restored MapValue
	err = json.Unmarshal(data, &restored)
	require.NoError(t, err)

	assert.Equal(t, val, restored)
}
