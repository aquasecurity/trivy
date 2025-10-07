package vex_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http/httptest"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/in-toto/in-toto-golang/in_toto"
	openvex "github.com/openvex/go-vex/pkg/vex"
	"github.com/package-url/packageurl-go"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/testdocker/auth"
	"github.com/aquasecurity/testdocker/registry"
	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/purl"
	"github.com/aquasecurity/trivy/pkg/vex"
)

func setUpRegistry(t *testing.T) (*httptest.Server, v1.Hash) {
	imgWithVEX := setUpImage(t)
	d, err := imgWithVEX.Digest()
	require.NoError(t, err)

	images := map[string]v1.Image{
		"v2/debian:latest":                            imgWithVEX,
		"v2/debian:no-vex":                            setUpImage(t),
		fmt.Sprintf("v2/debian@%s", d.String()):       imgWithVEX,
		fmt.Sprintf("v2/debian:sha256-%s.att", d.Hex): setUpVEXAttestation(t), // VEX attestation
	}

	tr := registry.NewDockerRegistry(registry.Option{
		Images: images,
		Auth:   auth.Auth{},
	})

	return tr, d
}

func setUpImage(t *testing.T) v1.Image {
	img, err := random.Image(100, 1, random.WithSource(rand.NewSource(0)))
	require.NoError(t, err)

	return img
}

func setUpVEXAttestation(t *testing.T) v1.Image {
	envelope := createVEXAttestation(t)
	b, err := json.Marshal(envelope)
	require.NoError(t, err)

	layer := static.NewLayer(b, "application/vnd.dsse.envelope.v1+json")
	newImage, err := mutate.AppendLayers(empty.Image, layer)
	require.NoError(t, err)

	return newImage
}

func createVEXAttestation(t *testing.T) dsse.Envelope {
	var v openvex.VEX
	testutil.MustReadJSON(t, "testdata/openvex-oci.json", &v)

	// in-toto Statement
	statement := in_toto.Statement{
		StatementHeader: in_toto.StatementHeader{
			Type:          "https://in-toto.io/Statement/v0.1",
			PredicateType: "https://openvex.dev/ns",
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

func TestRetrieveVEXAttestation(t *testing.T) {
	tr, _ := setUpRegistry(t)
	t.Cleanup(tr.Close)

	tests := []struct {
		name    string
		url     string
		wantErr require.ErrorAssertionFunc
	}{
		{
			name:    "vex found",
			url:     strings.TrimPrefix(tr.URL, "http://") + "/debian:latest",
			wantErr: require.NoError,
		},
		{
			name:    "vex not found",
			url:     strings.TrimPrefix(tr.URL, "http://") + "/debian:no-vex",
			wantErr: require.NoError,
		},
		{
			name:    "image not found",
			url:     strings.TrimPrefix(tr.URL, "http://") + "/debian:no-such-image",
			wantErr: require.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &purl.PackageURL{
				Type: packageurl.TypeOCI,
				Name: "debian",
				Qualifiers: packageurl.Qualifiers{
					{
						Key:   "repository_url",
						Value: tt.url,
					},
				},
			}
			_, err := vex.RetrieveVEXAttestation(p)
			tt.wantErr(t, err)
		})
	}
}
