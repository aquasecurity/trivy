package vex

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/hashicorp/go-multierror"
	"github.com/in-toto/in-toto-golang/in_toto"
	openvex "github.com/openvex/go-vex/pkg/vex"
	"github.com/package-url/packageurl-go"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/purl"
	"github.com/aquasecurity/trivy/pkg/remote"
	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	sigstoreBundleMediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"
	dsseEnvelopeMediaType   = "application/vnd.dsse.envelope.v1+json"
)

var supportedVEXArtifactTypes = []string{
	sigstoreBundleMediaType,
	dsseEnvelopeMediaType,
}

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
	return retrieveVEXAttestation(context.Background(), p, ftypes.RegistryOptions{})
}

func retrieveVEXAttestation(ctx context.Context, p *purl.PackageURL, registryOptions ftypes.RegistryOptions) (*OpenVEX, error) {
	var purlString string
	if p != nil {
		purlString = p.String()
	}
	logger := log.WithPrefix("vex").With(log.String("type", "oci"),
		log.String("purl", purlString))

	digest, registryOptions, err := resolveDigest(ctx, p, registryOptions)
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

func resolveDigest(ctx context.Context, p *purl.PackageURL, registryOptions ftypes.RegistryOptions) (name.Digest, ftypes.RegistryOptions, error) {
	ociPURL := p.Unwrap()
	if ociPURL == nil {
		return name.Digest{}, registryOptions, xerrors.New("package URL is nil")
	}
	if ociPURL.Type != packageurl.TypeOCI {
		return name.Digest{}, registryOptions, xerrors.Errorf("unsupported package URL type: %s", ociPURL.Type)
	}

	repoURL := ociPURL.Qualifiers.Map()["repository_url"]
	if repoURL == "" {
		return name.Digest{}, registryOptions, xerrors.New("repository_url qualifier is missing")
	}

	var insecure bool
	repoURL, insecure = normalizeRepositoryURL(repoURL)
	if insecure {
		registryOptions.Insecure = true
	}

	nameOpts := nameOptions(registryOptions)
	ref, err := name.ParseReference(repoURL, nameOpts...)
	if err != nil {
		return name.Digest{}, registryOptions, xerrors.Errorf("repository URL parse error: %w", err)
	}

	if ociPURL.Version != "" {
		return ref.Context().Digest(ociPURL.Version), registryOptions, nil
	}

	if digest, ok := ref.(name.Digest); ok {
		return digest, registryOptions, nil
	}

	desc, err := remote.Get(ctx, ref, registryOptions)
	if err != nil {
		return name.Digest{}, registryOptions, xerrors.Errorf("image get error: %w", err)
	}
	return ref.Context().Digest(desc.Digest.String()), registryOptions, nil
}

func normalizeRepositoryURL(repoURL string) (string, bool) {
	u, err := url.Parse(repoURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return repoURL, false
	}

	normalized := u.Host + u.EscapedPath()
	return normalized, u.Scheme == "http"
}

func nameOptions(registryOptions ftypes.RegistryOptions) []name.Option {
	var opts []name.Option
	if registryOptions.Insecure {
		opts = append(opts, name.Insecure)
	}
	return opts
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

	blob, err := fetchAttestationBlob(ctx, ref, registryOptions)
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	return decodeOpenVEXAttestation(blob, dsseEnvelopeMediaType)
}

func fetchAttestationBlob(ctx context.Context, ref name.Reference, registryOptions ftypes.RegistryOptions) ([]byte, error) {
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
	if len(layers) != 1 {
		return nil, xerrors.Errorf("OCI artifact must be a single layer")
	}

	rc, err := layers[0].Uncompressed()
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

type sigstoreBundle struct {
	MediaType    string          `json:"mediaType"`
	DSSEEnvelope json.RawMessage `json:"dsseEnvelope"`
}

func decodeOpenVEXAttestation(blob []byte, artifactType string) (*openvex.VEX, error) {
	if artifactType == sigstoreBundleMediaType {
		var bundle sigstoreBundle
		if err := json.NewDecoder(bytes.NewReader(blob)).Decode(&bundle); err != nil {
			return nil, xerrors.Errorf("failed to decode Sigstore bundle: %w", err)
		}
		if bundle.MediaType != "" && bundle.MediaType != sigstoreBundleMediaType {
			return nil, xerrors.Errorf("unexpected Sigstore bundle media type: %s", bundle.MediaType)
		}
		if len(bundle.DSSEEnvelope) == 0 {
			return nil, xerrors.New("Sigstore bundle is missing dsseEnvelope")
		}
		blob = bundle.DSSEEnvelope
	}

	return decodeDSSEOpenVEX(blob)
}

type openVEXStatement struct {
	in_toto.StatementHeader
	Predicate openvex.VEX `json:"predicate"`
}

func decodeDSSEOpenVEX(blob []byte) (*openvex.VEX, error) {
	var envelope dsse.Envelope
	if err := json.NewDecoder(bytes.NewReader(blob)).Decode(&envelope); err != nil {
		return nil, xerrors.Errorf("failed to decode as a DSSE envelope: %w", err)
	}
	if envelope.PayloadType != in_toto.PayloadType {
		return nil, xerrors.Errorf("invalid attestation payload type: %s", envelope.PayloadType)
	}

	decoded, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return nil, xerrors.Errorf("failed to decode attestation payload: %w", err)
	}

	var statement openVEXStatement
	if err = json.NewDecoder(bytes.NewReader(decoded)).Decode(&statement); err != nil {
		return nil, xerrors.Errorf("failed to decode attestation payload as in-toto statement: %w", err)
	}
	if !isOpenVEXPredicateType(statement.PredicateType) {
		return nil, xerrors.Errorf("unsupported predicate type: %s", statement.PredicateType)
	}

	return &statement.Predicate, nil
}

func isOpenVEXPredicateType(predicateType string) bool {
	return predicateType == openvex.TypeURI || strings.HasPrefix(predicateType, openvex.TypeURI+"/")
}

func isReferrersUnsupported(err error) bool {
	if isNotFound(err) {
		return true
	}

	var terr *transport.Error
	if !errorsAs(err, &terr) {
		return false
	}
	for _, diagnostic := range terr.Errors {
		if diagnostic.Code == transport.UnsupportedErrorCode {
			return true
		}
	}
	return false
}

func isNotFound(err error) bool {
	var terr *transport.Error
	if !errorsAs(err, &terr) {
		return false
	}
	if terr.StatusCode == 404 {
		return true
	}
	for _, diagnostic := range terr.Errors {
		if diagnostic.Code == transport.ManifestUnknownErrorCode || diagnostic.Code == transport.NameUnknownErrorCode {
			return true
		}
	}
	return false
}

func errorsAs(err error, target any) bool {
	if xerrors.As(err, target) {
		return true
	}

	var multiErr *multierror.Error
	if !xerrors.As(err, &multiErr) {
		return false
	}
	for _, e := range multiErr.Errors {
		if xerrors.As(e, target) {
			return true
		}
	}
	return false
}
