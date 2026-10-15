package types

import (
	"encoding/json/v2"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const encodedRange = `{"filename":"main.tf","startLine":2,"endLine":4,"sourcePrefix":"prefix","fsKey":"fs-key","isLogicalSource":true}`

func Test_RangeMarshalJSON(t *testing.T) {
	data, err := json.Marshal(newRange("main.tf", 2, 4, "prefix", "fs-key", nil, true))
	require.NoError(t, err)
	assert.JSONEq(t, encodedRange, string(data))
}

func Test_RangeUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    Range
		wantErr string
	}{
		{
			name:  "all fields",
			input: encodedRange,
			want:  newRange("main.tf", 2, 4, "prefix", "fs-key", nil, true),
		},
		{
			name:    "string line",
			input:   `{"startLine":"1"}`,
			wantErr: `within "/startLine"`,
		},
		{
			name:    "fractional line",
			input:   `{"startLine":1.5}`,
			wantErr: `within "/startLine"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Range
			err := json.Unmarshal([]byte(tt.input), &got)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
