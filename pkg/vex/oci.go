package vex

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	openvex "github.com/openvex/go-vex/pkg/vex"
	"github.com/package-url/packageurl-go"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/attestation"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/oci"
	"github.com/aquasecurity/trivy/pkg/purl"
	"github.com/aquasecurity/trivy/pkg/remote"
	"github.com/aquasecurity/trivy/pkg/types"
)

var supportedVEXArtifactTypes = []string{
	oci.SigstoreBundleArtifactType,
	oci.DSSEEnvelopeArtifactType,
}

// maxAttestationLayers bounds how many layers a legacy `.att` tag may stack
// before we refuse to process it. cosign caps the number of attestations per
// image at 100; mirror that to avoid unbounded layer fetches from a hostile
// registry. The referrer path needs no such cap: it fetches at most one
// candidate (it returns on the first supported referrer).
const maxAttestationLayers = 100

type OCI struct{}

func NewOCI(report *types.Report) (*OpenVEX, error) {
	if report.ArtifactType != ftypes.TypeContainerImage || len(report.Metadata.RepoDigests) == 0 {
		return nil, xerrors.New("'--vex oci' can be used only when scanning OCI artifacts stored in registries")
	}

	// TODO(knqyf263): Add the PURL field to Report.Metadata
	p, err := purl.New(purl.TypeOCI, report.Metadata, ftypes.Package{})
	if err != nil {
		return nil, xerrors.Errorf("failed to create a package URL: %w", err)
	}

	v, err := RetrieveVEXAttestation(p)
	if err != nil {
		return nil, xerrors.Errorf("failed to retrieve VEX attestation: %w", err)
	}
	return v, nil
}

func RetrieveVEXAttestation(p *purl.PackageURL) (*OpenVEX, error) {
	// TODO(#8916): thread the caller's RegistryOptions through so registry
	// credentials, --insecure and TLS settings reach the attestation fetch
	// instead of using an empty config.
	return retrieveVEXAttestation(context.Background(), p, ftypes.RegistryOptions{})
}

func retrieveVEXAttestation(ctx context.Context, p *purl.PackageURL, registryOptions ftypes.RegistryOptions) (*OpenVEX, error) {
	var purlString string
	if p != nil {
		purlString = p.String()
	}
	logger := log.WithPrefix("vex").With(log.String("type", "oci"),
		log.String("purl", purlString))

	digest, err := resolveDigest(ctx, p, registryOptions)
	if err != nil {
		return nil, xerrors.Errorf("failed to resolve OCI digest: %w", err)
	}

	vexDoc, err := retrieveReferrerVEX(ctx, digest, registryOptions)
	if err != nil {
		return nil, xerrors.Errorf("failed to retrieve VEX attestation from OCI referrers: %w", err)
	}
	if vexDoc == nil {
		vexDoc, err = retrieveLegacyVEX(ctx, digest, registryOptions)
		if err != nil {
			return nil, xerrors.Errorf("failed to retrieve VEX attestation from legacy tag: %w", err)
		}
	}
	if vexDoc == nil {
		logger.Info("No VEX attestations found")
		return nil, nil
	}

	logger.Debug("VEX attestation found")
	return &OpenVEX{
		vex:    *vexDoc,
		source: fmt.Sprintf("VEX attestation in OCI registry (%s)", p.String()),
	}, nil
}

func resolveDigest(ctx context.Context, p *purl.PackageURL, registryOptions ftypes.RegistryOptions) (name.Digest, error) {
	ociPURL := p.Unwrap()
	if ociPURL == nil {
		return name.Digest{}, xerrors.New("package URL is nil")
	}
	if ociPURL.Type != packageurl.TypeOCI {
		return name.Digest{}, xerrors.Errorf("unsupported package URL type: %s", ociPURL.Type)
	}

	repoURL := ociPURL.Qualifiers.Map()["repository_url"]
	if repoURL == "" {
		return name.Digest{}, xerrors.New("repository_url qualifier is missing")
	}

	ref, err := name.ParseReference(repoURL)
	if err != nil {
		return name.Digest{}, xerrors.Errorf("repository URL parse error: %w", err)
	}

	// For an OCI purl the version, when set, is the image digest.
	if ociPURL.Version != "" {
		return ref.Context().Digest(ociPURL.Version), nil
	}

	// Otherwise resolve the reference to a digest: it may already be one, or a
	// tag that needs a registry lookup.
	if digest, ok := ref.(name.Digest); ok {
		return digest, nil
	}

	desc, err := remote.Get(ctx, ref, registryOptions)
	if err != nil {
		return name.Digest{}, xerrors.Errorf("image get error: %w", err)
	}
	return ref.Context().Digest(desc.Digest.String()), nil
}

func retrieveReferrerVEX(ctx context.Context, digest name.Digest, registryOptions ftypes.RegistryOptions) (*openvex.VEX, error) {
	index, err := remote.Referrers(ctx, digest, registryOptions)
	if err != nil {
		if isReferrersUnsupported(err) {
			log.WithPrefix("vex").Debug("OCI referrers are not available", log.Err(err))
			return nil, nil
		}
		return nil, xerrors.Errorf("unable to fetch referrers: %w", err)
	}

	manifest, err := index.IndexManifest()
	if err != nil {
		return nil, xerrors.Errorf("unable to get referrers manifest: %w", err)
	}
	if manifest == nil {
		return nil, nil
	}

	for _, desc := range manifest.Manifests {
		if !slices.Contains(supportedVEXArtifactTypes, desc.ArtifactType) {
			continue
		}

		ref := digest.Context().Digest(desc.Digest.String())
		blob, err := fetchAttestationBlob(ctx, ref, registryOptions)
		if err != nil {
			return nil, xerrors.Errorf("referrer blob error (%s): %w", desc.Digest.String(), err)
		}

		vexDoc, err := decodeOpenVEXAttestation(blob, desc.ArtifactType)
		if err != nil {
			return nil, xerrors.Errorf("referrer decode error (%s): %w", desc.Digest.String(), err)
		}
		return vexDoc, nil
	}

	return nil, nil
}

func retrieveLegacyVEX(ctx context.Context, digest name.Digest, registryOptions ftypes.RegistryOptions) (*openvex.VEX, error) {
	tag := strings.ReplaceAll(digest.DigestStr(), ":", "-") + ".att"
	ref := digest.Context().Tag(tag)

	layers, err := fetchAttestationLayers(ctx, ref, registryOptions)
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	if len(layers) > maxAttestationLayers {
		return nil, xerrors.Errorf("legacy attestation has too many layers: %d (max %d)", len(layers), maxAttestationLayers)
	}

	// A legacy cosign `.att` tag accumulates one layer per `cosign attest` call, so
	// an image may carry several attestations (e.g. an SBOM and an OpenVEX document)
	// as separate layers. Return the first layer that decodes to an OpenVEX document
	// and skip the rest; rejecting malformed layers is left to a follow-up.
	logger := log.WithPrefix("vex").With(log.String("type", "oci"))
	for _, layer := range layers {
		blob, err := readLayer(layer)
		if err != nil {
			return nil, err
		}
		// Legacy `.att` layers are always bare DSSE envelopes; the Sigstore
		// bundle format is only used for OCI 1.1 referrers.
		vexDoc, err := decodeOpenVEXAttestation(blob, oci.DSSEEnvelopeArtifactType)
		if err != nil {
			logger.Debug("Skipping legacy attestation layer", log.Err(err))
			continue
		}
		return vexDoc, nil
	}
	return nil, nil
}

// fetchAttestationBlob returns the content of a single-layer attestation
// artifact (an OCI 1.1 referrer manifest).
func fetchAttestationBlob(ctx context.Context, ref name.Reference, registryOptions ftypes.RegistryOptions) ([]byte, error) {
	layers, err := fetchAttestationLayers(ctx, ref, registryOptions)
	if err != nil {
		return nil, err
	}
	if len(layers) != 1 {
		return nil, xerrors.Errorf("OCI artifact must be a single layer")
	}
	return readLayer(layers[0])
}

// fetchAttestationLayers returns the layers of the attestation image referenced by ref.
func fetchAttestationLayers(ctx context.Context, ref name.Reference, registryOptions ftypes.RegistryOptions) ([]v1.Layer, error) {
	desc, err := remote.Get(ctx, ref, registryOptions)
	if err != nil {
		return nil, err
	}

	img, err := desc.Image()
	if err != nil {
		return nil, xerrors.Errorf("image error: %w", err)
	}

	layers, err := img.Layers()
	if err != nil {
		return nil, xerrors.Errorf("layers error: %w", err)
	}
	return layers, nil
}

func readLayer(layer v1.Layer) ([]byte, error) {
	rc, err := layer.Uncompressed()
	if err != nil {
		return nil, xerrors.Errorf("failed to fetch the layer: %w", err)
	}
	defer rc.Close()

	blob, err := io.ReadAll(rc)
	if err != nil {
		return nil, xerrors.Errorf("read layer error: %w", err)
	}
	return blob, nil
}

// decodeOpenVEXAttestation decodes an OpenVEX predicate from an attestation blob.
// The blob is either a Sigstore bundle (Cosign v3+ new format) wrapping a DSSE
// envelope, or a bare DSSE envelope (legacy `.att` / OCI 1.1 referrer). In both
// cases the DSSE payload is an in-toto Statement whose predicate is the OpenVEX
// document.
func decodeOpenVEXAttestation(blob []byte, artifactType string) (*openvex.VEX, error) {
	// Decode the in-toto predicate directly into the typed OpenVEX struct.
	var predicate openvex.VEX
	statement := attestation.Statement{Predicate: &predicate}

	if artifactType == oci.SigstoreBundleArtifactType {
		bundle := attestation.SigstoreBundle{DSSEEnvelope: statement}
		if err := json.Unmarshal(blob, &bundle); err != nil {
			return nil, xerrors.Errorf("failed to decode Sigstore bundle: %w", err)
		}
		statement = bundle.DSSEEnvelope
	} else if err := json.Unmarshal(blob, &statement); err != nil {
		return nil, xerrors.Errorf("failed to decode DSSE envelope: %w", err)
	}

	if !isOpenVEXPredicateType(statement.PredicateType) {
		return nil, xerrors.Errorf("unsupported predicate type: %s", statement.PredicateType)
	}

	return &predicate, nil
}

// isOpenVEXPredicateType reports whether predicateType identifies an OpenVEX
// document. Besides the bare type URI, OpenVEX uses versioned namespaces such as
// "https://openvex.dev/ns/v0.2.0", so the prefix is accepted too. The trailing
// "/" keeps look-alikes like "https://openvex.dev/nsx" from matching.
func isOpenVEXPredicateType(predicateType string) bool {
	return predicateType == openvex.TypeURI || strings.HasPrefix(predicateType, openvex.TypeURI+"/")
}

// isReferrersUnsupported reports whether err means the registry has no OCI 1.1
// referrers for the digest (the API is not implemented or nothing is attached).
func isReferrersUnsupported(err error) bool {
	return isNotFound(err) || hasErrorCode(err, transport.UnsupportedErrorCode)
}

func isNotFound(err error) bool {
	var terr *transport.Error
	if !errors.As(err, &terr) {
		return false
	}
	return terr.StatusCode == http.StatusNotFound ||
		hasErrorCode(err, transport.ManifestUnknownErrorCode, transport.NameUnknownErrorCode)
}

// hasErrorCode reports whether err (or anything it wraps, including a
// multierror) is a registry transport error carrying one of the given codes.
func hasErrorCode(err error, codes ...transport.ErrorCode) bool {
	var terr *transport.Error
	if !errors.As(err, &terr) {
		return false
	}
	return slices.ContainsFunc(terr.Errors, func(d transport.Diagnostic) bool {
		return slices.Contains(codes, d.Code)
	})
}
