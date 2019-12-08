package client

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/twitchtv/twirp"
)

func TestWithToken(t *testing.T) {
	type args struct {
		ctx   context.Context
		token string
	}
	tests := []struct {
		name string
		args args
		want http.Header
	}{
		{
			name: "happy path",
			args: args{
				ctx:   context.Background(),
				token: "token",
			},
			want: http.Header{
				"Trivy-Token": []string{"token"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithToken(tt.args.ctx, tt.args.token)
			header, _ := twirp.HTTPRequestHeaders(got)
			assert.Equal(t, header, tt.want, tt.name)
		})
	}
}
