package registry

import (
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestGetToken(t *testing.T) {
	type args struct {
		domain string
		opt    types.RegistryOptions
	}
	tests := []struct {
		name     string
		args     args
		wantAuth authn.Basic
	}{
		{
			name: "happy path",
			args: args{
				domain: "docker.io",
			},
			wantAuth: authn.Basic{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotAuth := GetToken(t.Context(), tt.args.domain, tt.args.opt)
			assert.Equal(t, tt.wantAuth, gotAuth)
		})
	}
}
