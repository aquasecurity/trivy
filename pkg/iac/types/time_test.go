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

func Test_RFC3339TimeJSON(t *testing.T) {
	tests := []struct {
		name    string
		time    time.Time
		encoded string
	}{
		{
			name:    "zero time",
			time:    time.Time{},
			encoded: `"0001-01-01T00:00:00Z"`,
		},
		{
			name:    "utc",
			time:    time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC),
			encoded: `"2020-01-02T03:04:05Z"`,
		},
		{
			name:    "with offset",
			time:    time.Date(2020, 1, 2, 3, 4, 5, 0, time.FixedZone("", 2*60*60)),
			encoded: `"2020-01-02T03:04:05+02:00"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(RFC3339Time{tt.time})
			require.NoError(t, err)
			assert.Equal(t, tt.encoded, string(data))

			var restored RFC3339Time
			require.NoError(t, json.Unmarshal(data, &restored))
			assert.True(t, tt.time.Equal(restored.Time), "want %s, got %s", tt.time, restored.Time)
		})
	}
}

func Test_RFC3339TimeUnmarshalNull(t *testing.T) {
	ts := RFC3339Time{time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)}
	require.NoError(t, json.Unmarshal([]byte("null"), &ts))
	assert.True(t, ts.IsZero())
}
