package client

import (
	"context"
	"net/http"
	"os"
	"testing"

	"github.com/twitchtv/twirp"

	"github.com/aquasecurity/trivy/pkg/log"

	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	_ = log.InitLogger(false, true)
	os.Exit(m.Run())
}

func TestWithToken(t *testing.T) {
	type args struct {
		ctx         context.Context
		token       string
		tokenHeader string
	}
	tests := []struct {
		name string
		args args
		want http.Header
	}{
		{
			name: "happy path",
			args: args{
				ctx:         context.Background(),
				token:       "token",
				tokenHeader: "Trivy-Token",
			},
			want: http.Header{
				"Trivy-Token": []string{"token"},
			},
		},
		{
			name: "sad path, invalid headers passed in",
			args: args{
				ctx:         context.Background(),
				token:       "token",
				tokenHeader: "Content-Type",
			},
			want: http.Header(nil),
		},
	}
	for _, tt := range tests {
		gotCtx := WithToken(tt.args.ctx, tt.args.token, tt.args.tokenHeader)
		header, _ := twirp.HTTPRequestHeaders(gotCtx)
		assert.Equal(t, tt.want, header, tt.name)
	}
}
