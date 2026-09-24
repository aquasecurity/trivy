package image

import (
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/stretchr/testify/assert"
)

func TestAttestationOnlyManifest(t *testing.T) {
	tests := []struct {
		name     string
		manifest *v1.Manifest
		want     bool
	}{
		{
			name:     "nil manifest",
			manifest: nil,
			want:     false,
		},
		{
			name:     "no layers",
			manifest: &v1.Manifest{},
			want:     false,
		},
		{
			name: "real image layer",
			manifest: &v1.Manifest{
				Layers: []v1.Descriptor{
					{MediaType: "application/vnd.oci.image.layer.v1.tar+gzip"},
				},
			},
			want: false,
		},
		{
			name: "in-toto attestation only",
			manifest: &v1.Manifest{
				Layers: []v1.Descriptor{
					{MediaType: "application/vnd.in-toto+json"},
					{MediaType: "application/vnd.in-toto+json"},
				},
			},
			want: true,
		},
		{
			name: "mixed known attestation types",
			manifest: &v1.Manifest{
				Layers: []v1.Descriptor{
					{MediaType: "application/vnd.in-toto+json"},
					{MediaType: "application/spdx+json"},
				},
			},
			want: true,
		},
		{
			name: "real layer alongside an attestation-shaped one",
			manifest: &v1.Manifest{
				Layers: []v1.Descriptor{
					{MediaType: "application/vnd.oci.image.layer.v1.tar+gzip"},
					{MediaType: "application/vnd.in-toto+json"},
				},
			},
			want: false,
		},
		{
			name: "unrecognized media type is never assumed to be an attestation",
			manifest: &v1.Manifest{
				Layers: []v1.Descriptor{
					{MediaType: "application/x-some-custom-layer-type"},
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, attestationOnlyManifest(tt.manifest))
		})
	}
}
