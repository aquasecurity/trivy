package io_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/x/io"
)

func TestReadAllWithLimit(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		limit     int64
		want      string
		wantError bool
		wantLimit int64
	}{
		{name: "empty input at zero limit", limit: 0},
		{name: "input below limit", input: "abc", limit: 4, want: "abc"},
		{name: "input exactly at limit", input: "abc", limit: 3, want: "abc"},
		{name: "input over limit", input: "abcd", limit: 3, want: "abc", wantError: true, wantLimit: 3},
		{name: "negative limit", input: "a", limit: -1, wantError: true, wantLimit: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := io.ReadAllWithLimit(strings.NewReader(tt.input), tt.limit)
			assert.Equal(t, tt.want, string(got))
			if !tt.wantError {
				require.NoError(t, err)
				return
			}

			require.ErrorIs(t, err, io.ErrLimitExceeded)
			var maxErr *io.MaxBytesError
			require.ErrorAs(t, err, &maxErr)
			assert.Equal(t, tt.wantLimit, maxErr.Limit)
		})
	}
}
