// Package registrytest provides utilities for testing with OCI registries.
package registrytest

import (
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/require"
)

// NewServer starts a test registry server with OCI 1.1 referrers support.
func NewServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(registry.New(registry.WithReferrersSupport(true)))
}

// PushRandomImage pushes a random image to the registry and returns its reference and descriptor.
func PushRandomImage(t *testing.T, registryHost, repo, tag string) (name.Reference, v1.Descriptor) {
	t.Helper()

	ref, err := name.ParseReference(fmt.Sprintf("%s/%s:%s", registryHost, repo, tag))
	require.NoError(t, err)

	img, err := random.Image(10, 1)
	require.NoError(t, err)

	err = remote.Write(ref, img)
	require.NoError(t, err)

	d, err := img.Digest()
	require.NoError(t, err)
	sz, err := img.Size()
	require.NoError(t, err)
	mt, err := img.MediaType()
	require.NoError(t, err)

	return ref, v1.Descriptor{
		Digest:    d,
		Size:      sz,
		MediaType: mt,
	}
}

// PushReferrer pushes an artifact referrer to the registry attached to the subject image.
// The artifactType is used both as the config media type (for OCI 1.1 artifact type) and layer media type.
func PushReferrer(t *testing.T, registryHost, repo string, subjectDesc v1.Descriptor, artifactType string, content []byte) {
	t.Helper()

	// Create an OCI artifact with the content as a layer
	layer := static.NewLayer(content, types.MediaType(artifactType))

	// Start with an empty image and add the layer
	img := mutate.MediaType(empty.Image, types.OCIManifestSchema1)
	// Set the config media type to the artifact type - this is how OCI 1.1 identifies the artifact type
	// The registry will use this as the artifactType in the referrers API response
	img = mutate.ConfigMediaType(img, types.MediaType(artifactType))
	img, err := mutate.AppendLayers(img, layer)
	require.NoError(t, err)

	// Set the subject to create the referrer relationship
	img = mutate.Subject(img, subjectDesc).(v1.Image)

	// Push the referrer
	d, err := img.Digest()
	require.NoError(t, err)
	ref, err := name.ParseReference(fmt.Sprintf("%s/%s@%s", registryHost, repo, d.String()))
	require.NoError(t, err)

	err = remote.Write(ref, img)
	require.NoError(t, err)
}
