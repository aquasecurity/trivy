// Package registrytest provides utilities for testing with OCI registries.
package registrytest

import (
	"fmt"
	"net/http"
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

// NewServerWithAuth starts a test registry server with OCI 1.1 referrers support
// that requires the given credentials via HTTP basic auth.
func NewServerWithAuth(t *testing.T, user, password string) *httptest.Server {
	t.Helper()

	reg := registry.New(registry.WithReferrersSupport(true))
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser, gotPassword, ok := r.BasicAuth()
		if !ok || gotUser != user || gotPassword != password {
			w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		reg.ServeHTTP(w, r)
	})
	return httptest.NewServer(handler)
}

// PushImage pushes the given image to the registry and returns its reference and descriptor.
func PushImage(t *testing.T, registryHost, repo, tag string, img v1.Image, opts ...remote.Option) (name.Reference, v1.Descriptor) {
	t.Helper()

	ref, err := name.ParseReference(fmt.Sprintf("%s/%s:%s", registryHost, repo, tag))
	require.NoError(t, err)
	require.NoError(t, remote.Write(ref, img, opts...))

	return ref, descriptor(t, img)
}

// PushRandomImage pushes a random image to the registry and returns its reference and descriptor.
func PushRandomImage(t *testing.T, registryHost, repo, tag string, opts ...remote.Option) (name.Reference, v1.Descriptor) {
	t.Helper()

	img, err := random.Image(10, 1)
	require.NoError(t, err)

	return PushImage(t, registryHost, repo, tag, img, opts...)
}

// PushReferrer pushes an artifact referrer to the registry attached to the subject image.
// The artifactType is used both as the config media type (for OCI 1.1 artifact type) and layer media type.
func PushReferrer(t *testing.T, registryHost, repo string, subjectDesc v1.Descriptor, artifactType string, content []byte, opts ...remote.Option) {
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

	require.NoError(t, remote.Write(ref, img, opts...))
}

// PushLegacyAttestation pushes an image as a legacy cosign `.att` attestation for
// the given subject digest (the `<algorithm>-<hex>.att` tag convention).
func PushLegacyAttestation(t *testing.T, registryHost, repo string, subjectDigest v1.Hash, img v1.Image, opts ...remote.Option) {
	t.Helper()

	tag := fmt.Sprintf("%s-%s.att", subjectDigest.Algorithm, subjectDigest.Hex)
	ref, err := name.ParseReference(fmt.Sprintf("%s/%s:%s", registryHost, repo, tag))
	require.NoError(t, err)
	require.NoError(t, remote.Write(ref, img, opts...))
}

func descriptor(t *testing.T, img v1.Image) v1.Descriptor {
	t.Helper()

	d, err := img.Digest()
	require.NoError(t, err)
	sz, err := img.Size()
	require.NoError(t, err)
	mt, err := img.MediaType()
	require.NoError(t, err)

	return v1.Descriptor{
		Digest:    d,
		Size:      sz,
		MediaType: mt,
	}
}
