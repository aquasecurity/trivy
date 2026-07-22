package oci_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	ggcrremote "github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/in-toto/in-toto-golang/in_toto"
	openvex "github.com/openvex/go-vex/pkg/vex"
	"github.com/package-url/packageurl-go"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/registrytest"
	"github.com/aquasecurity/trivy/internal/testutil"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	coreoci "github.com/aquasecurity/trivy/pkg/oci"
	"github.com/aquasecurity/trivy/pkg/purl"
	"github.com/aquasecurity/trivy/pkg/vex/oci"
)

func setUpVEXAttestation(t *testing.T) v1.Image {
	return setUpVEXAttestationWithVulnerability(t, "CVE-2022-3715")
}

func setUpVEXAttestationWithVulnerability(t *testing.T, vulnerabilityID string) v1.Image {
	envelope := createVEXAttestation(t, vulnerabilityID)
	b, err := json.Marshal(envelope)
	require.NoError(t, err)

	layer := static.NewLayer(b, coreoci.DSSEEnvelopeArtifactType)
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
	sbomLayer := static.NewLayer(sbomBytes, coreoci.DSSEEnvelopeArtifactType)

	vexEnvelope := createVEXAttestation(t, vulnerabilityID)
	vexBytes, err := json.Marshal(vexEnvelope)
	require.NoError(t, err)
	vexLayer := static.NewLayer(vexBytes, coreoci.DSSEEnvelopeArtifactType)

	newImage, err := mutate.AppendLayers(empty.Image, sbomLayer, vexLayer)
	require.NoError(t, err)

	return newImage
}

func createVEXAttestation(t *testing.T, vulnerabilityID string) dsse.Envelope {
	return createVEXAttestationWithPredicateType(t, vulnerabilityID, "https://openvex.dev/ns")
}

func createVEXAttestationWithPredicateType(t *testing.T, vulnerabilityID, predicateType string) dsse.Envelope {
	// A DSSE envelope wraps the base64-encoded bare in-toto statement.
	return dsse.Envelope{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     base64.StdEncoding.EncodeToString(createBareInTotoStatement(t, vulnerabilityID, predicateType)),
		Signatures:  nil,
	}
}

func createVEXAttestationBlob(t *testing.T, vulnerabilityID string) []byte {
	b, err := json.Marshal(createVEXAttestation(t, vulnerabilityID))
	require.NoError(t, err)
	return b
}

// createBareInTotoStatement builds an in-toto statement stored as-is, without a
// DSSE envelope around it. Docker Scout attaches attestations to Docker Hardened
// Images this way. Its predicate is the OpenVEX document from the shared fixture.
func createBareInTotoStatement(t *testing.T, vulnerabilityID, predicateType string) []byte {
	var v openvex.VEX
	testutil.MustReadJSON(t, "../testdata/openvex-oci.json", &v)
	v.Statements[0].Vulnerability.Name = openvex.VulnerabilityID(vulnerabilityID)

	b, err := json.Marshal(in_toto.Statement{
		StatementHeader: in_toto.StatementHeader{
			Type:          "https://in-toto.io/Statement/v0.1",
			PredicateType: predicateType,
			Subject: []in_toto.Subject{
				{
					Name:   "example",
					Digest: map[string]string{"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
				},
			},
		},
		Predicate: v,
	})
	require.NoError(t, err)
	return b
}

func createSigstoreBundleVEXAttestation(t *testing.T, vulnerabilityID string) []byte {
	return createSigstoreBundleAttestationWithPredicateType(t, vulnerabilityID, "https://openvex.dev/ns")
}

func createSigstoreBundleAttestationWithPredicateType(t *testing.T, vulnerabilityID, predicateType string) []byte {
	bundle := struct {
		MediaType    string        `json:"mediaType"`
		DSSEEnvelope dsse.Envelope `json:"dsseEnvelope"`
	}{
		MediaType:    coreoci.SigstoreBundleArtifactType,
		DSSEEnvelope: createVEXAttestationWithPredicateType(t, vulnerabilityID, predicateType),
	}
	b, err := json.Marshal(bundle)
	require.NoError(t, err)
	return b
}

// setUpReferrerRegistry starts an OCI registry with referrers support and
// returns its host. If credentials are provided, the registry requires them via
// basic auth.
func setUpReferrerRegistry(t *testing.T, user, password string) string {
	var ts *httptest.Server
	if user == "" {
		ts = registrytest.NewServer(t)
	} else {
		ts = registrytest.NewServerWithAuth(t, user, password)
	}
	t.Cleanup(ts.Close)

	u, err := url.Parse(ts.URL)
	require.NoError(t, err)
	return u.Host
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

func requireOpenVEXMatch(t *testing.T, got *openvex.VEX, vulnerabilityID string) {
	t.Helper()
	require.NotNil(t, got)

	matches := got.Matches(vulnerabilityID, "pkg:oci/debian", []string{"pkg:deb/debian/bash"})
	require.Len(t, matches, 1)
}

func requireNoOpenVEXMatch(t *testing.T, got *openvex.VEX, vulnerabilityID string) {
	t.Helper()
	require.NotNil(t, got)

	matches := got.Matches(vulnerabilityID, "pkg:oci/debian", []string{"pkg:deb/debian/bash"})
	require.Empty(t, matches)
}

func TestDiscover(t *testing.T) {
	registryHost := setUpReferrerRegistry(t, "", "")

	tests := []struct {
		name    string
		setup   func(t *testing.T) string // pushes fixtures and returns the repository_url to query
		wantErr string
		want    map[string]bool // vulnerability ID -> whether it should match; nil means no VEX document is expected
	}{
		{
			name: "legacy attestation",
			setup: func(t *testing.T) string {
				repo := "debian/legacy"
				_, subjectDesc := registrytest.PushRandomImage(t, registryHost, repo, "latest")
				registrytest.PushLegacyAttestation(t, registryHost, repo, subjectDesc.Digest, setUpVEXAttestation(t))
				return registryHost + "/" + repo + ":latest"
			},
			want: map[string]bool{"CVE-2022-3715": true},
		},
		{
			name: "no attestation",
			setup: func(t *testing.T) string {
				repo := "debian/no-vex"
				registrytest.PushRandomImage(t, registryHost, repo, "latest")
				return registryHost + "/" + repo + ":latest"
			},
			want: nil,
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
				_, subjectDesc := registrytest.PushRandomImage(t, registryHost, repo, "latest")
				registrytest.PushReferrer(t, registryHost, repo, subjectDesc, coreoci.SigstoreBundleArtifactType,
					createSigstoreBundleVEXAttestation(t, "CVE-2022-3715"))
				return registryHost + "/" + repo + ":latest"
			},
			want: map[string]bool{"CVE-2022-3715": true},
		},
		{
			name: "referrer DSSE envelope",
			setup: func(t *testing.T) string {
				repo := "debian/dsse-envelope"
				_, subjectDesc := registrytest.PushRandomImage(t, registryHost, repo, "latest")
				registrytest.PushReferrer(t, registryHost, repo, subjectDesc, coreoci.DSSEEnvelopeArtifactType,
					createVEXAttestationBlob(t, "CVE-2022-3715"))
				return registryHost + "/" + repo + ":latest"
			},
			want: map[string]bool{"CVE-2022-3715": true},
		},
		{
			name: "referrer bare in-toto statement",
			setup: func(t *testing.T) string {
				repo := "debian/bare-in-toto"
				_, subjectDesc := registrytest.PushRandomImage(t, registryHost, repo, "latest")
				registrytest.PushReferrer(t, registryHost, repo, subjectDesc, coreoci.InTotoArtifactType,
					createBareInTotoStatement(t, "CVE-2022-3715", "https://openvex.dev/ns/v0.2.0"))
				return registryHost + "/" + repo + ":latest"
			},
			want: map[string]bool{"CVE-2022-3715": true},
		},
		{
			name: "referrer DSSE envelope under the in-toto artifact type",
			setup: func(t *testing.T) string {
				repo := "debian/in-toto-dsse"
				_, subjectDesc := registrytest.PushRandomImage(t, registryHost, repo, "latest")
				// The generic in-toto artifact type also carries DSSE envelopes,
				// depending on the publishing tool, so the format is detected by content.
				registrytest.PushReferrer(t, registryHost, repo, subjectDesc, coreoci.InTotoArtifactType,
					createVEXAttestationBlob(t, "CVE-2022-3715"))
				return registryHost + "/" + repo + ":latest"
			},
			want: map[string]bool{"CVE-2022-3715": true},
		},
		{
			name: "non-OpenVEX in-toto referrer is skipped",
			setup: func(t *testing.T) string {
				repo := "debian/in-toto-sbom"
				_, subjectDesc := registrytest.PushRandomImage(t, registryHost, repo, "latest")
				registrytest.PushReferrer(t, registryHost, repo, subjectDesc, coreoci.InTotoArtifactType,
					createBareInTotoStatement(t, "CVE-2022-3715", "https://spdx.dev/Document"))
				return registryHost + "/" + repo + ":latest"
			},
			want: nil,
		},
		{
			name: "undecodable referrer does not fail the scan",
			setup: func(t *testing.T) string {
				repo := "debian/undecodable-referrer"
				_, subjectDesc := registrytest.PushRandomImage(t, registryHost, repo, "latest")
				// A referrer Trivy cannot decode - here an unannotated blob in an unknown
				// format - must be skipped so that the remaining ones are still examined.
				registrytest.PushReferrer(t, registryHost, repo, subjectDesc, coreoci.InTotoArtifactType,
					[]byte(`{"mediaType":"application/vnd.oci.image.manifest.v1+json"}`))
				registrytest.PushReferrer(t, registryHost, repo, subjectDesc, coreoci.InTotoArtifactType,
					createBareInTotoStatement(t, "CVE-2022-3715", "https://openvex.dev/ns/v0.2.0"))
				return registryHost + "/" + repo + ":latest"
			},
			want: map[string]bool{"CVE-2022-3715": true},
		},
		{
			name: "referrer preferred over legacy",
			setup: func(t *testing.T) string {
				repo := "debian/prefer-referrer"
				_, subjectDesc := registrytest.PushRandomImage(t, registryHost, repo, "latest")
				registrytest.PushReferrer(t, registryHost, repo, subjectDesc, coreoci.SigstoreBundleArtifactType,
					createSigstoreBundleVEXAttestation(t, "CVE-2022-REFERRER"))
				registrytest.PushLegacyAttestation(t, registryHost, repo, subjectDesc.Digest,
					setUpVEXAttestationWithVulnerability(t, "CVE-2022-LEGACY"))
				return registryHost + "/" + repo + ":latest"
			},
			want: map[string]bool{
				"CVE-2022-REFERRER": true,
				"CVE-2022-LEGACY":   false,
			},
		},
		{
			name: "legacy multi-layer attestation",
			setup: func(t *testing.T) string {
				repo := "debian/multi-layer"
				_, subjectDesc := registrytest.PushRandomImage(t, registryHost, repo, "latest")
				registrytest.PushLegacyAttestation(t, registryHost, repo, subjectDesc.Digest,
					setUpMultiLayerVEXAttestation(t, "CVE-2022-3715"))
				return registryHost + "/" + repo + ":latest"
			},
			want: map[string]bool{"CVE-2022-3715": true},
		},
		{
			name: "legacy with no OpenVEX layer",
			setup: func(t *testing.T) string {
				repo := "debian/legacy-no-vex"
				_, subjectDesc := registrytest.PushRandomImage(t, registryHost, repo, "latest")
				// A `.att` whose only layer is a non-OpenVEX (e.g. SBOM) attestation.
				envelope := createVEXAttestationWithPredicateType(t, "CVE-2022-3715", "https://spdx.dev/Document")
				b, err := json.Marshal(envelope)
				require.NoError(t, err)
				img, err := mutate.AppendLayers(empty.Image, static.NewLayer(b, coreoci.DSSEEnvelopeArtifactType))
				require.NoError(t, err)
				registrytest.PushLegacyAttestation(t, registryHost, repo, subjectDesc.Digest, img)
				return registryHost + "/" + repo + ":latest"
			},
			want: nil,
		},
		{
			name: "legacy with too many layers",
			setup: func(t *testing.T) string {
				repo := "debian/too-many-layers"
				_, subjectDesc := registrytest.PushRandomImage(t, registryHost, repo, "latest")
				layers := make([]v1.Layer, 0, 101)
				for range 101 {
					layers = append(layers, static.NewLayer([]byte("x"), coreoci.DSSEEnvelopeArtifactType))
				}
				img, err := mutate.AppendLayers(empty.Image, layers...)
				require.NoError(t, err)
				registrytest.PushLegacyAttestation(t, registryHost, repo, subjectDesc.Digest, img)
				return registryHost + "/" + repo + ":latest"
			},
			wantErr: "too many layers",
		},
		{
			name: "malformed sigstore bundle is skipped",
			setup: func(t *testing.T) string {
				repo := "debian/malformed"
				_, subjectDesc := registrytest.PushRandomImage(t, registryHost, repo, "latest")
				registrytest.PushReferrer(t, registryHost, repo, subjectDesc, coreoci.SigstoreBundleArtifactType, []byte("{"))
				return registryHost + "/" + repo + ":latest"
			},
			want: nil,
		},
		{
			name: "non-OpenVEX referrer falls back to legacy",
			setup: func(t *testing.T) string {
				repo := "debian/sbom-referrer-then-legacy"
				_, subjectDesc := registrytest.PushRandomImage(t, registryHost, repo, "latest")
				// A Cosign v3 SBOM attestation shares the Sigstore bundle artifact
				// type; it must be skipped and discovery must fall back to legacy.
				registrytest.PushReferrer(t, registryHost, repo, subjectDesc, coreoci.SigstoreBundleArtifactType,
					createSigstoreBundleAttestationWithPredicateType(t, "CVE-2022-3715", "https://spdx.dev/Document"))
				registrytest.PushLegacyAttestation(t, registryHost, repo, subjectDesc.Digest, setUpVEXAttestation(t))
				return registryHost + "/" + repo + ":latest"
			},
			want: map[string]bool{"CVE-2022-3715": true},
		},
		{
			name: "oversized attestation exceeds size limit",
			setup: func(t *testing.T) string {
				repo := "debian/oversized"
				_, subjectDesc := registrytest.PushRandomImage(t, registryHost, repo, "latest")
				// A syntactically valid DSSE envelope whose payload exceeds
				// maxAttestationSize, generated on the fly (no fixture). Decoding must be
				// bounded and fail rather than read it all into memory.
				envelope := fmt.Appendf(nil, `{"payloadType":%q,"payload":%q,"signatures":null}`,
					"application/vnd.in-toto+json", strings.Repeat("A", 21<<20))
				registrytest.PushReferrer(t, registryHost, repo, subjectDesc, coreoci.DSSEEnvelopeArtifactType, envelope)
				return registryHost + "/" + repo + ":latest"
			},
			wantErr: "read limit exceeded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repoURL := tt.setup(t)
			got, err := oci.Discover(t.Context(), purlFromRepositoryURL(repoURL), ftypes.RegistryOptions{})
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			if tt.want == nil {
				require.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			for id, shouldMatch := range tt.want {
				if shouldMatch {
					requireOpenVEXMatch(t, got, id)
				} else {
					requireNoOpenVEXMatch(t, got, id)
				}
			}
		})
	}
}

func TestDiscoverByDigest(t *testing.T) {
	registryHost := setUpReferrerRegistry(t, "", "")

	repo := "debian/by-digest"
	_, subjectDesc := registrytest.PushRandomImage(t, registryHost, repo, "latest")
	registrytest.PushLegacyAttestation(t, registryHost, repo, subjectDesc.Digest, setUpVEXAttestation(t))

	// For an OCI purl the version, when set, is the image digest.
	p := &purl.PackageURL{
		Type:    packageurl.TypeOCI,
		Name:    "debian",
		Version: subjectDesc.Digest.String(),
		Qualifiers: packageurl.Qualifiers{
			{Key: "repository_url", Value: registryHost + "/" + repo},
		},
	}

	got, err := oci.Discover(t.Context(), p, ftypes.RegistryOptions{})
	require.NoError(t, err)
	requireOpenVEXMatch(t, got, "CVE-2022-3715")
}

func TestDiscoverWithRegistryAuth(t *testing.T) {
	const (
		user     = "test"
		password = "testpass"
	)

	registryHost := setUpReferrerRegistry(t, user, password)
	auth := ggcrremote.WithAuth(&authn.Basic{
		Username: user,
		Password: password,
	})

	repo := "debian/private"
	_, subjectDesc := registrytest.PushRandomImage(t, registryHost, repo, "latest", auth)
	registrytest.PushReferrer(t, registryHost, repo, subjectDesc, coreoci.SigstoreBundleArtifactType,
		createSigstoreBundleVEXAttestation(t, "CVE-2022-3715"), auth)
	setUpDockerConfig(t, registryHost, user, password)

	got, err := oci.Discover(t.Context(), purlFromRepositoryURL(registryHost+"/"+repo+":latest"), ftypes.RegistryOptions{})
	require.NoError(t, err)
	requireOpenVEXMatch(t, got, "CVE-2022-3715")
}

func TestDiscoverInvalidPURL(t *testing.T) {
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
			name: "invalid repository_url",
			purl: &purl.PackageURL{
				Type: packageurl.TypeOCI,
				Name: "debian",
				Qualifiers: packageurl.Qualifiers{
					{Key: "repository_url", Value: "not a valid reference"},
				},
			},
			wantErr: "repository URL parse error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := oci.Discover(t.Context(), tt.purl, ftypes.RegistryOptions{})
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestVEXCandidates(t *testing.T) {
	desc := func(name string, annotations map[string]string) v1.Descriptor {
		return v1.Descriptor{
			Digest:      v1.Hash{Algorithm: "sha256", Hex: name},
			Annotations: annotations,
		}
	}
	predicate := func(predicateType string) map[string]string {
		return map[string]string{coreoci.PredicateTypeAnnotation: predicateType}
	}

	tests := []struct {
		name  string
		descs []v1.Descriptor
		want  []string // digest hexes, in the expected order
	}{
		{
			name: "referrer announcing OpenVEX is kept",
			descs: []v1.Descriptor{
				desc("vex", predicate("https://openvex.dev/ns/v0.2.0")),
			},
			want: []string{"vex"},
		},
		{
			name: "referrers announcing another predicate are dropped",
			descs: []v1.Descriptor{
				desc("sbom", predicate("https://spdx.dev/Document")),
				desc("provenance", predicate("https://slsa.dev/provenance/v1")),
				desc("vex", predicate("https://openvex.dev/ns")),
			},
			want: []string{"vex"},
		},
		{
			name: "a look-alike namespace is not OpenVEX",
			descs: []v1.Descriptor{
				desc("lookalike", predicate("https://openvex.dev/nsx")),
			},
			want: nil,
		},
		{
			name: "the annotation is optional, so unannotated referrers are kept",
			descs: []v1.Descriptor{
				desc("unannotated", nil),
				desc("empty-annotations", make(map[string]string)),
			},
			want: []string{"unannotated", "empty-annotations"},
		},
		{
			name: "referrers announcing OpenVEX are probed before unannotated ones",
			descs: []v1.Descriptor{
				desc("unannotated", nil),
				desc("sbom", predicate("https://spdx.dev/Document")),
				desc("vex", predicate("https://openvex.dev/ns/v0.2.0")),
			},
			want: []string{"vex", "unannotated"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []string
			for _, d := range oci.VEXCandidates(tt.descs) {
				got = append(got, d.Digest.Hex)
			}
			require.Equal(t, tt.want, got)
		})
	}
}

func TestDecodeInTotoPredicate(t *testing.T) {
	tests := []struct {
		name              string
		blob              []byte
		wantPredicateType string
		wantErr           string
		wantMatch         bool // the OpenVEX predicate was decoded into the output
	}{
		{
			name:              "bare in-toto statement",
			blob:              createBareInTotoStatement(t, "CVE-2022-3715", "https://openvex.dev/ns"),
			wantPredicateType: "https://openvex.dev/ns",
			wantMatch:         true,
		},
		{
			name:              "DSSE envelope",
			blob:              createVEXAttestationBlob(t, "CVE-2022-3715"),
			wantPredicateType: "https://openvex.dev/ns",
			wantMatch:         true,
		},
		{
			name:              "bare statement with a non-OpenVEX predicate",
			blob:              createBareInTotoStatement(t, "CVE-2022-3715", "https://spdx.dev/Document"),
			wantPredicateType: "https://spdx.dev/Document",
		},
		{
			name:    "malformed JSON",
			blob:    []byte("{"),
			wantErr: "failed to decode attestation",
		},
		{
			name:    "neither a DSSE envelope nor an in-toto statement",
			blob:    []byte(`{"mediaType":"application/vnd.oci.image.manifest.v1+json"}`),
			wantErr: "unknown attestation format",
		},
		{
			name:    "DSSE envelope with a non-base64 payload",
			blob:    []byte(`{"payloadType":"application/vnd.in-toto+json","payload":"!!!not-base64!!!"}`),
			wantErr: "failed to decode DSSE envelope",
		},
		{
			name:    "DSSE envelope with the wrong payload type",
			blob:    []byte(`{"payloadType":"application/vnd.other+json","payload":"e30="}`),
			wantErr: "failed to decode DSSE envelope",
		},
		{
			name:    "bare statement with a malformed body",
			blob:    []byte(`{"_type":"https://in-toto.io/Statement/v0.1","subject":"not-an-array"}`),
			wantErr: "failed to decode in-toto statement",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var predicate openvex.VEX
			predicateType, err := oci.DecodeInTotoPredicate(tt.blob, &predicate)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantPredicateType, predicateType)
			if tt.wantMatch {
				requireOpenVEXMatch(t, &predicate, "CVE-2022-3715")
			}
		})
	}
}
