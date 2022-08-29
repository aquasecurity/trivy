package daemon

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/docker/api/types"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

func TestDockerImage(t *testing.T) {
	type fields struct {
		Image   v1.Image
		opener  opener
		inspect types.ImageInspect
	}
	tests := []struct {
		name      string
		imageName string
		fields    fields
		want      *v1.ConfigFile
		wantErr   bool
	}{
		{
			name:      "happy path",
			imageName: "alpine:3.11",
			wantErr:   false,
		},
		{
			name:      "unknown image",
			imageName: "alpine:unknown",
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref, err := name.ParseReference(tt.imageName)
			require.NoError(t, err)

			_, cleanup, err := DockerImage(ref)
			assert.Equal(t, tt.wantErr, err != nil, err)
			defer func() {
				if cleanup != nil {
					cleanup()
				}
			}()
		})
	}
}
