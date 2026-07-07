package oci

import (
	"context"
	"encoding/json"
	"errors"
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
	coreoci "github.com/aquasecurity/trivy/pkg/oci"
	"github.com/aquasecurity/trivy/pkg/purl"
	"github.com/aquasecurity/trivy/pkg/remote"
	"github.com/aquasecurity/trivy/pkg/set"
)

var supportedVEXArtifactTypes = set.New(
	coreoci.SigstoreBundleArtifactType,
	coreoci.DSSEEnvelopeArtifactType,
)

const (
	// maxAttestations bounds how many attestations we will fetch and decode for a
	// single image before giving up, applied to both legacy `.att` layers and OCI
	// 1.1 referrers carrying a VEX artifact type. cosign caps the number of
	// attestations per image at 100; mirror that to avoid unbounded fetches from a
	// hostile registry that attaches many non-OpenVEX attestations.
	maxAttestations = 100

	// maxAttestationSize bounds the uncompressed size of a single attestation layer
	// read into memory, guarding against decompression bombs (CWE-409) served by a
	// hostile registry. OpenVEX documents are small (KiB-MiB).
	maxAttestationSize = 50 << 20 // 50 MiB
)

// Discover fetches the OpenVEX document attached to an OCI artifact, addressed by
// its package URL, using the given registry options for authentication and
// transport. It looks for a Cosign v3 attestation stored as an OCI 1.1 referrer
// first, then falls back to the legacy Cosign v2 `.att` tag, and returns nil when
// no VEX attestation is found.
func Discover(ctx context.Context, p *purl.PackageURL, opts ftypes.RegistryOptions) (*openvex.VEX, error) {
	if p == nil {
		return nil, xerrors.New("package URL is nil")
	}
	logger := log.WithPrefix("vex").With(log.String("type", "oci"),
		log.String("purl", p.String()))

	digest, err := resolveDigest(ctx, p, opts)
	if err != nil {
		return nil, xerrors.Errorf("failed to resolve OCI digest: %w", err)
	}

	vexDoc, err := retrieveReferrerVEX(ctx, digest, opts)
	if err != nil {
		return nil, xerrors.Errorf("failed to retrieve VEX attestation from OCI referrers: %w", err)
	}
	if vexDoc == nil {
		vexDoc, err = retrieveLegacyVEX(ctx, digest, opts)
		if err != nil {
			return nil, xerrors.Errorf("failed to retrieve VEX attestation from legacy tag: %w", err)
		}
	}
	if vexDoc == nil {
		logger.Info("No VEX attestations found")
		return nil, nil
	}

	logger.Debug("VEX attestation found")
	return vexDoc, nil
}

func resolveDigest(ctx context.Context, p *purl.PackageURL, registryOptions ftypes.RegistryOptions) (name.Digest, error) {
	ociPURL := p.Unwrap()
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
		if isReferrersUnavailable(err) {
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

	// A VEX artifact type (Sigstore bundle / DSSE envelope) is shared by every
	// Cosign attestation, not just VEX, so an image may expose SBOM or SLSA
	// provenance referrers alongside (or instead of) a VEX one. Decode each
	// candidate and return the first OpenVEX document, skipping the rest; cap the
	// number processed so a hostile registry cannot make us fetch unboundedly.
	processed := 0
	for _, desc := range manifest.Manifests {
		if !supportedVEXArtifactTypes.Contains(desc.ArtifactType) {
			continue
		}
		if processed >= maxAttestations {
			return nil, xerrors.Errorf("too many VEX referrers: processed %d (max %d)", processed, maxAttestations)
		}
		processed++

		ref := digest.Context().Digest(desc.Digest.String())
		blob, err := fetchAttestationBlob(ctx, ref, registryOptions)
		if err != nil {
			return nil, xerrors.Errorf("referrer blob error (%s): %w", desc.Digest.String(), err)
		}

		vexDoc, err := decodeOpenVEXAttestation(blob, desc.ArtifactType)
		if err != nil {
			return nil, xerrors.Errorf("referrer decode error (%s): %w", desc.Digest.String(), err)
		}
		if vexDoc == nil {
			continue // a valid attestation, but not OpenVEX (e.g. SBOM); try the next referrer
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
	if len(layers) > maxAttestations {
		return nil, xerrors.Errorf("legacy attestation has too many layers: %d (max %d)", len(layers), maxAttestations)
	}

	// A legacy cosign `.att` tag accumulates one layer per `cosign attest` call, so
	// an image may carry several attestations (e.g. an SBOM and an OpenVEX document)
	// as separate layers. Return the first layer that decodes to an OpenVEX document;
	// skip layers that are not OpenVEX or that fail to decode.
	logger := log.WithPrefix("vex").With(log.String("type", "oci"))
	for _, layer := range layers {
		blob, err := readLayer(layer, maxAttestationSize)
		if err != nil {
			return nil, err
		}
		// Legacy `.att` layers are always bare DSSE envelopes; the Sigstore
		// bundle format is only used for OCI 1.1 referrers.
		vexDoc, err := decodeOpenVEXAttestation(blob, coreoci.DSSEEnvelopeArtifactType)
		if err != nil {
			logger.Debug("Skipping malformed legacy attestation layer", log.Err(err))
			continue
		}
		if vexDoc == nil {
			continue // a valid attestation, but not OpenVEX (e.g. SBOM); try the next layer
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
		return nil, xerrors.New("OCI artifact must be a single layer")
	}
	return readLayer(layers[0], maxAttestationSize)
}

// fetchAttestationLayers returns the layers of the attestation image at the given reference.
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

func readLayer(layer v1.Layer, maxSize int) ([]byte, error) {
	rc, err := layer.Uncompressed()
	if err != nil {
		return nil, xerrors.Errorf("failed to fetch the layer: %w", err)
	}
	defer rc.Close()

	blob, err := io.ReadAll(io.LimitReader(rc, int64(maxSize)+1))
	if err != nil {
		return nil, xerrors.Errorf("read layer error: %w", err)
	}
	if len(blob) > maxSize {
		return nil, xerrors.Errorf("attestation layer exceeds the size limit of %d bytes", maxSize)
	}
	return blob, nil
}

// decodeOpenVEXAttestation decodes an OpenVEX predicate from an attestation blob.
// The blob is either a Sigstore bundle (Cosign v3+ new format) wrapping a DSSE
// envelope, or a bare DSSE envelope (legacy `.att` / OCI 1.1 referrer). In both
// cases the DSSE payload is an in-toto Statement whose predicate is the OpenVEX
// document.
//
// It returns (nil, nil) when the attestation is well-formed but its predicate is
// not OpenVEX (e.g. an SBOM or SLSA provenance attestation sharing the same
// artifact type), so callers can skip it. An error is returned only when the
// blob itself cannot be decoded.
func decodeOpenVEXAttestation(blob []byte, artifactType string) (*openvex.VEX, error) {
	// Decode the in-toto predicate directly into the typed OpenVEX struct.
	var predicate openvex.VEX
	statement := attestation.Statement{Predicate: &predicate}

	if artifactType == coreoci.SigstoreBundleArtifactType {
		bundle := attestation.SigstoreBundle{DSSEEnvelope: statement}
		if err := json.Unmarshal(blob, &bundle); err != nil {
			return nil, xerrors.Errorf("failed to decode Sigstore bundle: %w", err)
		}
		statement = bundle.DSSEEnvelope
	} else if err := json.Unmarshal(blob, &statement); err != nil {
		return nil, xerrors.Errorf("failed to decode DSSE envelope: %w", err)
	}

	if !isOpenVEXPredicateType(statement.PredicateType) {
		return nil, nil
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

// isReferrersUnavailable reports whether err means the registry has no OCI 1.1
// referrers for the digest (the API is not implemented or nothing is attached).
func isReferrersUnavailable(err error) bool {
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
