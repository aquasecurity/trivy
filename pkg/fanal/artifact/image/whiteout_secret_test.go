package image_test

import (
	"archive/tar"
	"bytes"
	"io"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/cachetest"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/applier"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	image2 "github.com/aquasecurity/trivy/pkg/fanal/artifact/image"
)

const privateKey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEA07/9vAAAAfakekeydatapayload1234567890abcdef
-----END OPENSSH PRIVATE KEY-----
`

// TestArtifact_InspectDeletedSecret builds an image where a key is copied in one layer
// and removed in the next, as with `COPY id_rsa /app/` followed by `RUN rm /app/id_rsa`.
func TestArtifact_InspectDeletedSecret(t *testing.T) {
	const (
		addedBy   = "COPY id_rsa_private /app/id_rsa_private # buildkit"
		deletedBy = "RUN /bin/sh -c rm /app/id_rsa_private # buildkit"
	)

	img, err := mutate.Append(empty.Image,
		mutate.Addendum{
			Layer:   tarLayer(t, map[string]string{"app/id_rsa_private": privateKey}),
			History: v1.History{CreatedBy: addedBy},
		},
		mutate.Addendum{
			Layer:   tarLayer(t, map[string]string{"app/.wh.id_rsa_private": ""}),
			History: v1.History{CreatedBy: deletedBy},
		},
	)
	require.NoError(t, err)

	c := cachetest.NewCache(t, nil)
	a, err := image2.NewArtifact(&fakeImage{name: "whiteout-secret", Image: img}, c, artifact.Option{})
	require.NoError(t, err)

	ref, err := a.Inspect(t.Context())
	require.NoError(t, err)

	// The image has no OS, but the merged result is still returned.
	detail, err := applier.NewApplier(c).ApplyLayers(t.Context(), ref.ID, ref.BlobIDs)
	require.ErrorIs(t, err, analyzer.ErrUnknownOS)

	require.Len(t, detail.Secrets, 1)
	secret := detail.Secrets[0]
	assert.Equal(t, "/app/id_rsa_private", secret.FilePath)
	require.Len(t, secret.Findings, 1)

	finding := secret.Findings[0]
	assert.Equal(t, "private-key", finding.RuleID)
	assert.Equal(t, ref.ImageMetadata.DiffIDs[0], finding.Layer.DiffID)
	assert.Equal(t, addedBy, finding.Layer.CreatedBy)
	require.NotNil(t, finding.DeletedIn)
	assert.Equal(t, ref.ImageMetadata.DiffIDs[1], finding.DeletedIn.DiffID)
	assert.Equal(t, deletedBy, finding.DeletedIn.CreatedBy)
}

func tarLayer(t *testing.T, files map[string]string) v1.Layer {
	t.Helper()

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, content := range files {
		require.NoError(t, tw.WriteHeader(&tar.Header{
			Name:     name,
			Mode:     0o600,
			Size:     int64(len(content)),
			Typeflag: tar.TypeReg,
		}))
		_, err := tw.Write([]byte(content))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())

	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(buf.Bytes())), nil
	})
	require.NoError(t, err)
	return layer
}
