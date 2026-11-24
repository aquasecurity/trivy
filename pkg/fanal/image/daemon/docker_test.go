package daemon

import (
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDockerImage(t *testing.T) {
	type fields struct {
		Image  v1.Image
		opener opener
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

			_, cleanup, err := DockerImage(t.Context(), ref, "")
			assert.Equal(t, tt.wantErr, err != nil, err)
			defer func() {
				if cleanup != nil {
					cleanup()
				}
			}()
		})
	}
}

func Test_normalizeImageID(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "full image ID without sha256 prefix",
			input: "a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
			want:  "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
		},
		{
			name:  "full image ID with sha256 prefix",
			input: "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
			want:  "sha256:a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb72",
		},
		{
			name:  "short image ID",
			input: "a187dde48cd2",
			want:  "a187dde48cd2",
		},
		{
			name:  "63-hex image ID prefix",
			input: "a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb7",
			want:  "a187dde48cd289ac374ad8539930628314bc581a481cdb41409c9289419ddb7",
		},
		{
			name:  "image name",
			input: "alpine:3.11",
			want:  "alpine:3.11",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, normalizeImageID(tt.input))
		})
	}
}
