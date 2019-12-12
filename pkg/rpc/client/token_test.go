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
		ctx   context.Context
		token string
	}
	tests := []struct {
		name                   string
		args                   args
		buildRequestHeaderFunc func(map[string]string) http.Header
		want                   http.Header
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
			buildRequestHeaderFunc: buildRequestHeader,
		},
		{
			name: "sad path, invalid headers passed in",
			args: args{
				ctx:   context.Background(),
				token: "token",
			},
			want: http.Header(nil),
			buildRequestHeaderFunc: func(m map[string]string) http.Header {
				header := make(http.Header)
				for k, v := range m {
					header.Set(k, v)
				}

				// add an extra header that is reserved for twirp
				header.Set("Content-Type", "foobar")
				return header
			},
		},
	}
	for _, tt := range tests {
		oldbuildRequestHeaderFunc := buildRequestHeaderFunc
		defer func() {
			buildRequestHeaderFunc = oldbuildRequestHeaderFunc
		}()
		buildRequestHeaderFunc = tt.buildRequestHeaderFunc
		gotCtx := WithToken(tt.args.ctx, tt.args.token)
		header, _ := twirp.HTTPRequestHeaders(gotCtx)
		assert.Equal(t, tt.want, header, tt.name)
	}
}
