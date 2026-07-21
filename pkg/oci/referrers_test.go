package oci_test

import (
	"net/url"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/samber/lo"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/registrytest"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/oci"
	"github.com/aquasecurity/trivy/pkg/set"
)

func TestReferrers(t *testing.T) {
	ts := registrytest.NewServer(t)
	t.Cleanup(ts.Close)

	u, err := url.Parse(ts.URL)
	require.NoError(t, err)
	host := u.Host

	const (
		repo            = "test/referrers"
		unsupportedType = "application/vnd.example.unsupported"
	)
	ref, subjectDesc := registrytest.PushRandomImage(t, host, repo, "latest")
	// Two supported referrers of different artifact types, plus one unsupported
	// one that must always be filtered out.
	registrytest.PushReferrer(t, host, repo, subjectDesc, oci.SigstoreBundleArtifactType, []byte("bundle"))
	registrytest.PushReferrer(t, host, repo, subjectDesc, oci.DSSEEnvelopeArtifactType, []byte("dsse"))
	registrytest.PushReferrer(t, host, repo, subjectDesc, unsupportedType, []byte("other"))

	digest := ref.Context().Digest(subjectDesc.Digest.String())

	tests := []struct {
		name          string
		artifactTypes set.Set[string]
		want          []string // expected ArtifactTypes of the returned referrers
	}{
		{
			name:          "both supported types",
			artifactTypes: set.New(oci.SigstoreBundleArtifactType, oci.DSSEEnvelopeArtifactType),
			want:          []string{oci.SigstoreBundleArtifactType, oci.DSSEEnvelopeArtifactType},
		},
		{
			name:          "only sigstore bundle",
			artifactTypes: set.New(oci.SigstoreBundleArtifactType),
			want:          []string{oci.SigstoreBundleArtifactType},
		},
		{
			name:          "no matching type",
			artifactTypes: set.New("application/vnd.example.none"),
			want:          nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			descs, err := oci.Referrers(t.Context(), digest, ftypes.RegistryOptions{}, tt.artifactTypes)
			require.NoError(t, err)
			gotTypes := lo.Map(descs, func(desc v1.Descriptor, _ int) string {
				return desc.ArtifactType
			})
			require.ElementsMatch(t, tt.want, gotTypes)
		})
	}
}
