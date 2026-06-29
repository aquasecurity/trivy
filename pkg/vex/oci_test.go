package vex_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	ggcrremote "github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/static"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/hashicorp/go-multierror"
	"github.com/in-toto/in-toto-golang/in_toto"
	openvex "github.com/openvex/go-vex/pkg/vex"
	"github.com/package-url/packageurl-go"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/oci"
	"github.com/aquasecurity/trivy/pkg/purl"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
	ttypes "github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/vex"
)

func setUpRegistry(t *testing.T) (*httptest.Server, v1.Hash) {
	tr, registryHost := setUpReferrerRegistry(t, "", "")

	imgWithVEX := setUpImage(t)
	d, err := imgWithVEX.Digest()
	require.NoError(t, err)

	pushImage(t, registryHost, "debian", "latest", imgWithVEX)
	pushImage(t, registryHost, "debian", "no-vex", setUpImageWithSeed(t, 1))
	pushLegacyAttestation(t, registryHost, "debian", d, setUpVEXAttestation(t))

	return tr, d
}

func setUpImage(t *testing.T) v1.Image {
	return setUpImageWithSeed(t, 0)
}

func setUpImageWithSeed(t *testing.T, seed int64) v1.Image {
	img, err := random.Image(100, 1, random.WithSource(rand.NewSource(seed)))
	require.NoError(t, err)

	return img
}

func setUpVEXAttestation(t *testing.T) v1.Image {
	return setUpVEXAttestationWithVulnerability(t, "CVE-2022-3715")
}

func setUpVEXAttestationWithVulnerability(t *testing.T, vulnerabilityID string) v1.Image {
	envelope := createVEXAttestation(t, vulnerabilityID)
	b, err := json.Marshal(envelope)
	require.NoError(t, err)

	layer := static.NewLayer(b, oci.DSSEEnvelopeArtifactType)
	newImage, err := mutate.AppendLayers(empty.Image, layer)
	require.NoError(t, err)

	return newImage
}

// setUpMultiLayerVEXAttestation builds a legacy `.att` image whose layers stack
// a non-OpenVEX attestation (e.g. an SBOM) ahead of the OpenVEX one, mirroring
// an image that was attested with `cosign attest` more than once.
func setUpMultiLayerVEXAttestation(t *testing.T, vulnerabilityID string) v1.Image {
	sbomEnvelope := createVEXAttestationWithPredicateType(t, vulnerabilityID, "https://spdx.dev/Document")
	sbomBytes, err := json.Marshal(sbomEnvelope)
	require.NoError(t, err)
	sbomLayer := static.NewLayer(sbomBytes, oci.DSSEEnvelopeArtifactType)

	vexEnvelope := createVEXAttestation(t, vulnerabilityID)
	vexBytes, err := json.Marshal(vexEnvelope)
	require.NoError(t, err)
	vexLayer := static.NewLayer(vexBytes, oci.DSSEEnvelopeArtifactType)

	newImage, err := mutate.AppendLayers(empty.Image, sbomLayer, vexLayer)
	require.NoError(t, err)

	return newImage
}

func createVEXAttestation(t *testing.T, vulnerabilityID string) dsse.Envelope {
	return createVEXAttestationWithPredicateType(t, vulnerabilityID, "https://openvex.dev/ns")
}

func createVEXAttestationWithPredicateType(t *testing.T, vulnerabilityID, predicateType string) dsse.Envelope {
	var v openvex.VEX
	testutil.MustReadJSON(t, "testdata/openvex-oci.json", &v)
	v.Statements[0].Vulnerability.Name = openvex.VulnerabilityID(vulnerabilityID)

	// in-toto Statement
	statement := in_toto.Statement{
		StatementHeader: in_toto.StatementHeader{
			Type:          "https://in-toto.io/Statement/v0.1",
			PredicateType: predicateType,
			Subject: []in_toto.Subject{
				{
					Name: "example",
					Digest: map[string]string{
						"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
					},
				},
			},
		},
		Predicate: v,
	}

	attestationJSON, err := json.Marshal(statement)
	require.NoError(t, err)

	// Base64 encode
	encodedAttestation := base64.StdEncoding.EncodeToString(attestationJSON)

	// Create a DSSE envelope
	return dsse.Envelope{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     encodedAttestation,
		Signatures:  nil,
	}
}

func createVEXAttestationBlobWithPredicateType(t *testing.T, vulnerabilityID, predicateType string) []byte {
	b, err := json.Marshal(createVEXAttestationWithPredicateType(t, vulnerabilityID, predicateType))
	require.NoError(t, err)
	return b
}

func createVEXAttestationBlob(t *testing.T, vulnerabilityID string) []byte {
	b, err := json.Marshal(createVEXAttestation(t, vulnerabilityID))
	require.NoError(t, err)
	return b
}

func createSigstoreBundleVEXAttestation(t *testing.T, vulnerabilityID string) []byte {
	bundle := struct {
		MediaType    string        `json:"mediaType"`
		DSSEEnvelope dsse.Envelope `json:"dsseEnvelope"`
	}{
		MediaType:    oci.SigstoreBundleArtifactType,
		DSSEEnvelope: createVEXAttestation(t, vulnerabilityID),
	}
	b, err := json.Marshal(bundle)
	require.NoError(t, err)
	return b
}

// setUpReferrerRegistry starts an OCI registry with referrers support. When user
// is non-empty the registry requires the given basic-auth credentials.
func setUpReferrerRegistry(t *testing.T, user, password string) (*httptest.Server, string) {
	handler := registry.New(registry.WithReferrersSupport(true))
	if user != "" {
		registryHandler := handler
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotUser, gotPassword, ok := r.BasicAuth()
			if !ok || gotUser != user || gotPassword != password {
				w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			registryHandler.ServeHTTP(w, r)
		})
	}

	tr := httptest.NewServer(handler)
	t.Cleanup(tr.Close)

	u, err := url.Parse(tr.URL)
	require.NoError(t, err)
	return tr, u.Host
}

func pushRandomImage(t *testing.T, registryHost, repo, tag string, opts ...ggcrremote.Option) (name.Reference, v1.Descriptor) {
	return pushImage(t, registryHost, repo, tag, setUpImage(t), opts...)
}

func pushImage(t *testing.T, registryHost, repo, tag string, img v1.Image, opts ...ggcrremote.Option) (name.Reference, v1.Descriptor) {
	ref, err := name.ParseReference(fmt.Sprintf("%s/%s:%s", registryHost, repo, tag))
	require.NoError(t, err)
	require.NoError(t, ggcrremote.Write(ref, img, opts...))
	digest, err := img.Digest()
	require.NoError(t, err)
	size, err := img.Size()
	require.NoError(t, err)
	mediaType, err := img.MediaType()
	require.NoError(t, err)

	return ref, v1.Descriptor{
		Digest:    digest,
		Size:      size,
		MediaType: mediaType,
	}
}

func pushReferrer(t *testing.T, registryHost, repo string, subjectDesc v1.Descriptor, artifactType string, content []byte, opts ...ggcrremote.Option) {
	layer := static.NewLayer(content, v1types.MediaType(artifactType))

	img := mutate.MediaType(empty.Image, v1types.OCIManifestSchema1)
	img = mutate.ConfigMediaType(img, v1types.MediaType(artifactType))
	img, err := mutate.AppendLayers(img, layer)
	require.NoError(t, err)
	img = mutate.Subject(img, subjectDesc).(v1.Image)

	digest, err := img.Digest()
	require.NoError(t, err)
	ref, err := name.ParseReference(fmt.Sprintf("%s/%s@%s", registryHost, repo, digest.String()))
	require.NoError(t, err)

	require.NoError(t, ggcrremote.Write(ref, img, opts...))
}

func pushLegacyAttestation(t *testing.T, registryHost, repo string, subjectDigest v1.Hash, img v1.Image, opts ...ggcrremote.Option) {
	ref, err := name.ParseReference(fmt.Sprintf("%s/%s:sha256-%s.att", registryHost, repo, subjectDigest.Hex))
	require.NoError(t, err)

	require.NoError(t, ggcrremote.Write(ref, img, opts...))
}

func setUpDockerConfig(t *testing.T, registryHost, user, password string) {
	configDir := t.TempDir()
	t.Setenv("DOCKER_CONFIG", configDir)

	encoded := base64.StdEncoding.EncodeToString(fmt.Appendf(nil, "%s:%s", user, password))
	config := fmt.Sprintf(`{"auths":{%q:{"auth":%q}}}`, registryHost, encoded)
	require.NoError(t, os.WriteFile(filepath.Join(configDir, "config.json"), []byte(config), 0o600))
}

func purlFromRepositoryURL(repositoryURL string) *purl.PackageURL {
	return &purl.PackageURL{
		Type: packageurl.TypeOCI,
		Name: "debian",
		Qualifiers: packageurl.Qualifiers{
			{
				Key:   "repository_url",
				Value: repositoryURL,
			},
		},
	}
}

func componentWithPURL(t *testing.T, purlString string) *core.Component {
	p, err := packageurl.FromString(purlString)
	require.NoError(t, err)
	return &core.Component{
		PkgIdentifier: ftypes.PkgIdentifier{
			PURL: &p,
		},
	}
}

func requireOpenVEXMatch(t *testing.T, got *vex.OpenVEX, vulnerabilityID string) {
	t.Helper()
	require.NotNil(t, got)

	matches := got.Matches(ttypes.DetectedVulnerability{VulnerabilityID: vulnerabilityID},
		componentWithPURL(t, "pkg:oci/debian"), componentWithPURL(t, "pkg:deb/debian/bash"))
	require.Len(t, matches, 1)
}

func requireNoOpenVEXMatch(t *testing.T, got *vex.OpenVEX, vulnerabilityID string) {
	t.Helper()
	require.NotNil(t, got)

	matches := got.Matches(ttypes.DetectedVulnerability{VulnerabilityID: vulnerabilityID},
		componentWithPURL(t, "pkg:oci/debian"), componentWithPURL(t, "pkg:deb/debian/bash"))
	require.Empty(t, matches)
}

func TestRetrieveVEXAttestation(t *testing.T) {
	_, registryHost := setUpReferrerRegistry(t, "", "")

	tests := []struct {
		name        string
		setup       func(t *testing.T) string // pushes fixtures and returns the repository_url to query
		wantErr     string
		wantNil     bool
		wantMatch   []string
		wantNoMatch []string
	}{
		{
			name: "legacy attestation",
			setup: func(t *testing.T) string {
				repo := "debian/legacy"
				_, subjectDesc := pushRandomImage(t, registryHost, repo, "latest")
				pushLegacyAttestation(t, registryHost, repo, subjectDesc.Digest, setUpVEXAttestation(t))
				return registryHost + "/" + repo + ":latest"
			},
			wantMatch: []string{"CVE-2022-3715"},
		},
		{
			name: "no attestation",
			setup: func(t *testing.T) string {
				repo := "debian/no-vex"
				pushRandomImage(t, registryHost, repo, "latest")
				return registryHost + "/" + repo + ":latest"
			},
			wantNil: true,
		},
		{
			name: "image not found",
			setup: func(_ *testing.T) string {
				return registryHost + "/debian/missing:latest"
			},
			wantErr: "failed to resolve OCI digest",
		},
		{
			name: "referrer sigstore bundle",
			setup: func(t *testing.T) string {
				repo := "debian/sigstore-bundle"
				_, subjectDesc := pushRandomImage(t, registryHost, repo, "latest")
				pushReferrer(t, registryHost, repo, subjectDesc, oci.SigstoreBundleArtifactType,
					createSigstoreBundleVEXAttestation(t, "CVE-2022-3715"))
				return registryHost + "/" + repo + ":latest"
			},
			wantMatch: []string{"CVE-2022-3715"},
		},
		{
			name: "referrer DSSE envelope",
			setup: func(t *testing.T) string {
				repo := "debian/dsse-envelope"
				_, subjectDesc := pushRandomImage(t, registryHost, repo, "latest")
				pushReferrer(t, registryHost, repo, subjectDesc, oci.DSSEEnvelopeArtifactType,
					createVEXAttestationBlob(t, "CVE-2022-3715"))
				return registryHost + "/" + repo + ":latest"
			},
			wantMatch: []string{"CVE-2022-3715"},
		},
		{
			name: "referrer preferred over legacy",
			setup: func(t *testing.T) string {
				repo := "debian/prefer-referrer"
				_, subjectDesc := pushRandomImage(t, registryHost, repo, "latest")
				pushReferrer(t, registryHost, repo, subjectDesc, oci.SigstoreBundleArtifactType,
					createSigstoreBundleVEXAttestation(t, "CVE-2022-REFERRER"))
				pushLegacyAttestation(t, registryHost, repo, subjectDesc.Digest,
					setUpVEXAttestationWithVulnerability(t, "CVE-2022-LEGACY"))
				return registryHost + "/" + repo + ":latest"
			},
			wantMatch:   []string{"CVE-2022-REFERRER"},
			wantNoMatch: []string{"CVE-2022-LEGACY"},
		},
		{
			name: "legacy multi-layer attestation",
			setup: func(t *testing.T) string {
				repo := "debian/multi-layer"
				_, subjectDesc := pushRandomImage(t, registryHost, repo, "latest")
				pushLegacyAttestation(t, registryHost, repo, subjectDesc.Digest,
					setUpMultiLayerVEXAttestation(t, "CVE-2022-3715"))
				return registryHost + "/" + repo + ":latest"
			},
			wantMatch: []string{"CVE-2022-3715"},
		},
		{
			name: "legacy with no OpenVEX layer",
			setup: func(t *testing.T) string {
				repo := "debian/legacy-no-vex"
				_, subjectDesc := pushRandomImage(t, registryHost, repo, "latest")
				// A `.att` whose only layer is a non-OpenVEX (e.g. SBOM) attestation.
				envelope := createVEXAttestationWithPredicateType(t, "CVE-2022-3715", "https://spdx.dev/Document")
				b, err := json.Marshal(envelope)
				require.NoError(t, err)
				img, err := mutate.AppendLayers(empty.Image, static.NewLayer(b, oci.DSSEEnvelopeArtifactType))
				require.NoError(t, err)
				pushLegacyAttestation(t, registryHost, repo, subjectDesc.Digest, img)
				return registryHost + "/" + repo + ":latest"
			},
			wantNil: true,
		},
		{
			name: "legacy with too many layers",
			setup: func(t *testing.T) string {
				repo := "debian/too-many-layers"
				_, subjectDesc := pushRandomImage(t, registryHost, repo, "latest")
				layers := make([]v1.Layer, 0, 101)
				for range 101 {
					layers = append(layers, static.NewLayer([]byte("x"), oci.DSSEEnvelopeArtifactType))
				}
				img, err := mutate.AppendLayers(empty.Image, layers...)
				require.NoError(t, err)
				pushLegacyAttestation(t, registryHost, repo, subjectDesc.Digest, img)
				return registryHost + "/" + repo + ":latest"
			},
			wantErr: "too many layers",
		},
		{
			name: "malformed sigstore bundle",
			setup: func(t *testing.T) string {
				repo := "debian/malformed"
				_, subjectDesc := pushRandomImage(t, registryHost, repo, "latest")
				pushReferrer(t, registryHost, repo, subjectDesc, oci.SigstoreBundleArtifactType, []byte("{"))
				return registryHost + "/" + repo + ":latest"
			},
			wantErr: "failed to decode Sigstore bundle",
		},
		{
			name: "lookalike predicate type",
			setup: func(t *testing.T) string {
				repo := "debian/bad-predicate"
				_, subjectDesc := pushRandomImage(t, registryHost, repo, "latest")
				pushReferrer(t, registryHost, repo, subjectDesc, oci.DSSEEnvelopeArtifactType,
					createVEXAttestationBlobWithPredicateType(t, "CVE-2022-3715", "https://openvex.dev/nsx"))
				return registryHost + "/" + repo + ":latest"
			},
			wantErr: "unsupported predicate type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repoURL := tt.setup(t)
			got, err := vex.RetrieveVEXAttestation(t.Context(), purlFromRepositoryURL(repoURL))
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			if tt.wantNil {
				require.Nil(t, got)
				return
			}
			for _, id := range tt.wantMatch {
				requireOpenVEXMatch(t, got, id)
			}
			for _, id := range tt.wantNoMatch {
				requireNoOpenVEXMatch(t, got, id)
			}
		})
	}
}

func TestRetrieveVEXAttestationInvalidPURL(t *testing.T) {
	tests := []struct {
		name    string
		purl    *purl.PackageURL
		wantErr string
	}{
		{
			name:    "nil package URL",
			purl:    nil,
			wantErr: "package URL is nil",
		},
		{
			name:    "non-OCI package URL",
			purl:    &purl.PackageURL{Type: packageurl.TypeNPM, Name: "debian"},
			wantErr: "unsupported package URL type",
		},
		{
			name:    "missing repository_url qualifier",
			purl:    &purl.PackageURL{Type: packageurl.TypeOCI, Name: "debian"},
			wantErr: "repository_url qualifier is missing",
		},
		{
			name:    "invalid repository_url",
			purl:    purlFromRepositoryURL("not a valid reference"),
			wantErr: "repository URL parse error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := vex.RetrieveVEXAttestation(t.Context(), tt.purl)
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestRetrieveVEXAttestationWithRegistryAuth(t *testing.T) {
	const (
		user     = "test"
		password = "testpass"
	)

	_, registryHost := setUpReferrerRegistry(t, user, password)
	auth := ggcrremote.WithAuth(&authn.Basic{
		Username: user,
		Password: password,
	})

	repo := "debian/private"
	_, subjectDesc := pushRandomImage(t, registryHost, repo, "latest", auth)
	pushReferrer(t, registryHost, repo, subjectDesc, oci.SigstoreBundleArtifactType,
		createSigstoreBundleVEXAttestation(t, "CVE-2022-3715"), auth)
	setUpDockerConfig(t, registryHost, user, password)

	got, err := vex.RetrieveVEXAttestation(t.Context(), purlFromRepositoryURL(registryHost+"/"+repo+":latest"))
	require.NoError(t, err)
	requireOpenVEXMatch(t, got, "CVE-2022-3715")
}

func TestRetrieveVEXAttestationLayerTooLarge(t *testing.T) {
	vex.SetMaxAttestationSize(t, 16)

	_, registryHost := setUpReferrerRegistry(t, "", "")
	repo := "debian/oversized"
	_, subjectDesc := pushRandomImage(t, registryHost, repo, "latest")
	pushReferrer(t, registryHost, repo, subjectDesc, oci.SigstoreBundleArtifactType,
		createSigstoreBundleVEXAttestation(t, "CVE-2022-3715"))

	_, err := vex.RetrieveVEXAttestation(t.Context(), purlFromRepositoryURL(registryHost+"/"+repo+":latest"))
	require.ErrorContains(t, err, "exceeds the size limit")
}

func TestIsReferrersUnsupported(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "non-transport error",
			err:  errors.New("boom"),
			want: false,
		},
		{
			name: "404 Not Found",
			err:  &transport.Error{StatusCode: http.StatusNotFound},
			want: true,
		},
		{
			name: "MANIFEST_UNKNOWN code",
			err:  &transport.Error{Errors: []transport.Diagnostic{{Code: transport.ManifestUnknownErrorCode}}},
			want: true,
		},
		{
			name: "NAME_UNKNOWN code",
			err:  &transport.Error{Errors: []transport.Diagnostic{{Code: transport.NameUnknownErrorCode}}},
			want: true,
		},
		{
			name: "UNSUPPORTED code (referrers API not implemented)",
			err:  &transport.Error{Errors: []transport.Diagnostic{{Code: transport.UnsupportedErrorCode}}},
			want: true,
		},
		{
			name: "UNSUPPORTED wrapped in a multierror",
			err: multierror.Append(errors.New("auth attempt failed"),
				&transport.Error{Errors: []transport.Diagnostic{{Code: transport.UnsupportedErrorCode}}}),
			want: true,
		},
		{
			name: "other transport error",
			err:  &transport.Error{StatusCode: http.StatusInternalServerError},
			want: false,
		},
		{
			name: "unauthorized is not 'unsupported'",
			err:  &transport.Error{StatusCode: http.StatusUnauthorized, Errors: []transport.Diagnostic{{Code: transport.UnauthorizedErrorCode}}},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, vex.IsReferrersUnsupported(tt.err))
		})
	}
}
