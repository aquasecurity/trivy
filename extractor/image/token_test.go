package image

import (
	"context"
	"testing"

	"github.com/aquasecurity/fanal/types"
	imageTypes "github.com/containers/image/v5/types"
	"github.com/stretchr/testify/assert"
)

func TestGetToken(t *testing.T) {
	type args struct {
		domain string
		opt    types.DockerOption
	}
	tests := []struct {
		name     string
		args     args
		wantAuth *imageTypes.DockerAuthConfig
	}{
		{
			name: "happy path",
			args: args{
				domain: "docker.io",
			},
			wantAuth: nil,
		},
		{
			name: "happy path with a credential",
			args: args{
				domain: "docker.io",
				opt: types.DockerOption{
					UserName: "user",
					Password: "pass",
				},
			},
			wantAuth: &imageTypes.DockerAuthConfig{
				Username: "user",
				Password: "pass",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotAuth := GetToken(context.Background(), tt.args.domain, tt.args.opt)
			assert.Equal(t, tt.wantAuth, gotAuth)
		})
	}
}
