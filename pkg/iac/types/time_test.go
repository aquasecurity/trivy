package types

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_TimeJSON(t *testing.T) {
	val := Time(time.Now(), NewMetadata(NewRange("main.tf", 123, 123, "", nil), ""))
	data, err := json.Marshal(val)
	require.NoError(t, err)

	var restored TimeValue
	err = json.Unmarshal(data, &restored)
	require.NoError(t, err)

	assert.Equal(t, val.value.Format(time.RFC3339), restored.Value().Format(time.RFC3339))
	assert.Equal(t, val.metadata, restored.metadata)
}
