package image

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/samber/lo"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	sbomatt "github.com/aquasecurity/trivy/pkg/attestation/sbom"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact/sbom"
	"github.com/aquasecurity/trivy/pkg/fanal/log"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/oci"
	"github.com/aquasecurity/trivy/pkg/remote"
	"github.com/aquasecurity/trivy/pkg/types"
)

var errNoSBOMFound = xerrors.New("remote SBOM not found")

type inspectRemoteSBOM func(context.Context) (ftypes.ArtifactReference, error)

func (a Artifact) retrieveRemoteSBOM(ctx context.Context) (ftypes.ArtifactReference, error) {
	for _, sbomSource := range a.artifactOption.SBOMSources {
		var inspect inspectRemoteSBOM
		switch sbomSource {
		case types.SBOMSourceOCI:
			inspect = a.inspectOCIReferrerSBOM
		case types.SBOMSourceRekor:
			inspect = a.inspectRekorSBOMAttestation
		default:
			// Never reach here as the "--sbom-sources" values are validated beforehand
			continue
		}

		ref, err := inspect(ctx)
		if errors.Is(err, errNoSBOMFound) {
			// Try the next SBOM source
			log.Logger.Debugf("No SBOM found in the source: %s", sbomSource)
			continue
		} else if err != nil {
			return ftypes.ArtifactReference{}, xerrors.Errorf("SBOM searching error: %w", err)
		}
		return ref, nil
	}
	return ftypes.ArtifactReference{}, errNoSBOMFound
}

func (a Artifact) inspectOCIReferrerSBOM(ctx context.Context) (ftypes.ArtifactReference, error) {
	digest, err := repoDigest(a.image, a.artifactOption.Insecure)
	if err != nil {
		return ftypes.ArtifactReference{}, xerrors.Errorf("repo digest error: %w", err)
	}

	// Fetch referrers
	index, err := remote.Referrers(ctx, digest, a.artifactOption.RemoteOptions)
	if err != nil {
		return ftypes.ArtifactReference{}, xerrors.Errorf("unable to fetch referrers: %w", err)
	}
	for _, m := range lo.FromPtr(index).Manifests {
		// Unsupported artifact type
		if !slices.Contains(oci.SupportedSBOMArtifactTypes, m.ArtifactType) {
			continue
		}
		res, err := a.parseReferrer(ctx, digest.Context().String(), m)
		if err != nil {
			log.Logger.Warnf("Error with SBOM via OCI referrers (%s): %s", m.Digest.String(), err)
			continue
		}
		return res, nil
	}
	return ftypes.ArtifactReference{}, errNoSBOMFound
}

func (a Artifact) parseReferrer(ctx context.Context, repo string, desc v1.Descriptor) (ftypes.ArtifactReference, error) {
	const fileName string = "referrer.sbom"
	repoName := fmt.Sprintf("%s@%s", repo, desc.Digest)
	referrer, err := oci.NewArtifact(repoName, true, a.artifactOption.RemoteOptions)
	if err != nil {
		return ftypes.ArtifactReference{}, xerrors.Errorf("OCI error: %w", err)
	}

	tmpDir, err := os.MkdirTemp("", "trivy-sbom-*")
	if err != nil {
		return ftypes.ArtifactReference{}, xerrors.Errorf("mkdir temp error: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Download SBOM to local filesystem
	if err = referrer.Download(ctx, tmpDir, oci.DownloadOption{
		MediaType: desc.ArtifactType,
		Filename:  fileName,
	}); err != nil {
		return ftypes.ArtifactReference{}, xerrors.Errorf("SBOM download error: %w", err)
	}

	res, err := a.inspectSBOMFile(ctx, filepath.Join(tmpDir, fileName))
	if err != nil {
		return res, xerrors.Errorf("SBOM error: %w", err)
	}

	// Found SBOM
	log.Logger.Infof("Found SBOM (%s) in the OCI referrers", res.Type)

	return res, nil
}

func (a Artifact) inspectRekorSBOMAttestation(ctx context.Context) (ftypes.ArtifactReference, error) {
	digest, err := repoDigest(a.image, a.artifactOption.Insecure)
	if err != nil {
		return ftypes.ArtifactReference{}, xerrors.Errorf("repo digest error: %w", err)
	}

	client, err := sbomatt.NewRekor(a.artifactOption.RekorURL)
	if err != nil {
		return ftypes.ArtifactReference{}, xerrors.Errorf("failed to create rekor client: %w", err)
	}

	raw, err := client.RetrieveSBOM(ctx, digest.DigestStr())
	if errors.Is(err, sbomatt.ErrNoSBOMAttestation) {
		return ftypes.ArtifactReference{}, errNoSBOMFound
	} else if err != nil {
		return ftypes.ArtifactReference{}, xerrors.Errorf("failed to retrieve SBOM attestation: %w", err)
	}

	f, err := os.CreateTemp("", "sbom-*")
	if err != nil {
		return ftypes.ArtifactReference{}, xerrors.Errorf("failed to create a temporary file: %w", err)
	}
	defer os.Remove(f.Name())

	if _, err = f.Write(raw); err != nil {
		return ftypes.ArtifactReference{}, xerrors.Errorf("copy error: %w", err)
	}
	if err = f.Close(); err != nil {
		return ftypes.ArtifactReference{}, xerrors.Errorf("failed to close %s: %w", f.Name(), err)
	}
	res, err := a.inspectSBOMFile(ctx, f.Name())
	if err != nil {
		return res, xerrors.Errorf("SBOM error: %w", err)
	}

	// Found SBOM
	log.Logger.Infof("Found SBOM (%s) in Rekor (%s)", res.Type, a.artifactOption.RekorURL)

	return res, nil
}

func (a Artifact) inspectSBOMFile(ctx context.Context, filePath string) (ftypes.ArtifactReference, error) {
	ar, err := sbom.NewArtifact(filePath, a.cache, a.artifactOption)
	if err != nil {
		return ftypes.ArtifactReference{}, xerrors.Errorf("failed to new artifact: %w", err)
	}

	results, err := ar.Inspect(ctx)
	if err != nil {
		return ftypes.ArtifactReference{}, xerrors.Errorf("failed to inspect: %w", err)
	}
	results.Name = a.image.Name()

	return results, nil
}

func repoDigest(img ftypes.Image, insecure bool) (name.Digest, error) {
	repoNameFull := img.Name()
	ref, err := name.ParseReference(repoNameFull)
	if err != nil {
		return name.Digest{}, xerrors.Errorf("image name parse error: %w", err)
	}

	for _, rd := range img.RepoDigests() {
		opts := lo.Ternary(insecure, []name.Option{name.Insecure}, nil)
		digest, err := name.NewDigest(rd, opts...)
		if err != nil {
			continue
		}
		if ref.Context().String() == digest.Context().String() {
			return digest, nil
		}
	}
	return name.Digest{}, xerrors.Errorf("no repo digest found: %w", errNoSBOMFound)
}
