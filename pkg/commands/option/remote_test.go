package option

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_splitCustomHeaders(t *testing.T) {
	type args struct {
		headers []string
	}
	tests := []struct {
		name string
		args args
		want http.Header
	}{
		{
			name: "happy path",
			args: args{
				headers: []string{"x-api-token:foo bar", "Authorization:user:password"},
			},
			want: http.Header{
				"X-Api-Token":   []string{"foo bar"},
				"Authorization": []string{"user:password"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitCustomHeaders(tt.args.headers)
			assert.Equal(t, tt.want, got)
		})
	}
}
