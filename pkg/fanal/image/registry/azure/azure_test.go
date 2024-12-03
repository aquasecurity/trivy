package azure_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/image/registry/azure"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestRegistry_CheckOptions(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		wantErr string
	}{
		{
			name:   "happy path",
			domain: "test.azurecr.io",
		},
		{
			name:   "china happy path",
			domain: "test.azurecr.cn",
		},
		{
			name:    "invalidURL",
			domain:  "not-azurecr.io",
			wantErr: "Azure registry: invalid url pattern",
		},
		{
			name:    "invalidURL",
			domain:  "alpine:3.9",
			wantErr: "Azure registry: invalid url pattern",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := azure.Registry{}
			_, err := r.CheckOptions(tt.domain, types.RegistryOptions{})
			if tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
