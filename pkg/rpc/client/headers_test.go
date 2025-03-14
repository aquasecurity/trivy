package client

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/twitchtv/twirp"
)

func TestWithCustomHeaders(t *testing.T) {
	type args struct {
		ctx           context.Context
		customHeaders http.Header
	}
	tests := []struct {
		name string
		args args
		want http.Header
	}{
		{
			name: "happy path",
			args: args{
				ctx: t.Context(),
				customHeaders: http.Header{
					"Trivy-Token": []string{"token"},
				},
			},
			want: http.Header{
				"Trivy-Token": []string{"token"},
			},
		},
		{
			name: "sad path, invalid headers passed in",
			args: args{
				ctx: t.Context(),
				customHeaders: http.Header{
					"Content-Type": []string{"token"},
				},
			},
			want: http.Header(nil),
		},
	}
	for _, tt := range tests {
		gotCtx := WithCustomHeaders(tt.args.ctx, tt.args.customHeaders)
		header, _ := twirp.HTTPRequestHeaders(gotCtx)
		assert.Equal(t, tt.want, header, tt.name)
	}
}
