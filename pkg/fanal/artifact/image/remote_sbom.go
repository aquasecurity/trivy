package image

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	sbomatt "github.com/aquasecurity/trivy/pkg/attestation/sbom"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact/sbom"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/oci"
	"github.com/aquasecurity/trivy/pkg/remote"
	"github.com/aquasecurity/trivy/pkg/types"
)

var errNoSBOMFound = xerrors.New("remote SBOM not found")

type inspectRemoteSBOM func(context.Context) (artifact.Reference, error)

func (a Artifact) retrieveRemoteSBOM(ctx context.Context) (artifact.Reference, error) {
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
			a.logger.Debug("No SBOM found in the source", log.String("source", sbomSource))
			continue
		} else if err != nil {
			return artifact.Reference{}, xerrors.Errorf("SBOM searching error: %w", err)
		}
		return ref, nil
	}
	return artifact.Reference{}, errNoSBOMFound
}

func (a Artifact) inspectOCIReferrerSBOM(ctx context.Context) (artifact.Reference, error) {
	digest, err := repoDigest(a.image, a.artifactOption.Insecure)
	if err != nil {
		return artifact.Reference{}, xerrors.Errorf("repo digest error: %w", err)
	}

	// Fetch referrers
	index, err := remote.Referrers(ctx, digest, a.artifactOption.ImageOption.RegistryOptions)
	if err != nil {
		return artifact.Reference{}, xerrors.Errorf("unable to fetch referrers: %w", err)
	}
	manifest, err := index.IndexManifest()
	if err != nil {
		return artifact.Reference{}, xerrors.Errorf("unable to get manifest: %w", err)
	}
	for _, m := range lo.FromPtr(manifest).Manifests {
		// Unsupported artifact type
		if !slices.Contains(oci.SupportedSBOMArtifactTypes, m.ArtifactType) {
			continue
		}
		res, err := a.parseReferrer(ctx, digest.Context().String(), m)
		if err != nil {
			a.logger.Warn("Error with SBOM via OCI referrers",
				log.String("digest", m.Digest.String()), log.Err(err))
			continue
		}
		return res, nil
	}
	return artifact.Reference{}, errNoSBOMFound
}

func (a Artifact) parseReferrer(ctx context.Context, repo string, desc v1.Descriptor) (artifact.Reference, error) {
	const fileName string = "referrer.sbom"
	repoName := fmt.Sprintf("%s@%s", repo, desc.Digest)
	referrer, err := oci.NewArtifact(repoName, true, a.artifactOption.ImageOption.RegistryOptions)
	if err != nil {
		return artifact.Reference{}, xerrors.Errorf("OCI error: %w", err)
	}

	tmpDir, err := os.MkdirTemp("", "trivy-sbom-*")
	if err != nil {
		return artifact.Reference{}, xerrors.Errorf("mkdir temp error: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Download SBOM to local filesystem
	if err = referrer.Download(ctx, tmpDir, oci.DownloadOption{
		MediaType: desc.ArtifactType,
		Filename:  fileName,
	}); err != nil {
		return artifact.Reference{}, xerrors.Errorf("SBOM download error: %w", err)
	}

	res, err := a.inspectSBOMFile(ctx, filepath.Join(tmpDir, fileName))
	if err != nil {
		return res, xerrors.Errorf("SBOM error: %w", err)
	}

	// Found SBOM
	a.logger.Info("Found SBOM in the OCI referrers", log.String("type", string(res.Type)))

	return res, nil
}

func (a Artifact) inspectRekorSBOMAttestation(ctx context.Context) (artifact.Reference, error) {
	digest, err := repoDigest(a.image, a.artifactOption.Insecure)
	if err != nil {
		return artifact.Reference{}, xerrors.Errorf("repo digest error: %w", err)
	}

	client, err := sbomatt.NewRekor(a.artifactOption.RekorURL)
	if err != nil {
		return artifact.Reference{}, xerrors.Errorf("failed to create rekor client: %w", err)
	}

	raw, err := client.RetrieveSBOM(ctx, digest.DigestStr())
	if errors.Is(err, sbomatt.ErrNoSBOMAttestation) {
		return artifact.Reference{}, errNoSBOMFound
	} else if err != nil {
		return artifact.Reference{}, xerrors.Errorf("failed to retrieve SBOM attestation: %w", err)
	}

	f, err := os.CreateTemp("", "sbom-*")
	if err != nil {
		return artifact.Reference{}, xerrors.Errorf("failed to create a temporary file: %w", err)
	}
	defer os.Remove(f.Name())

	if _, err = f.Write(raw); err != nil {
		return artifact.Reference{}, xerrors.Errorf("copy error: %w", err)
	}
	if err = f.Close(); err != nil {
		return artifact.Reference{}, xerrors.Errorf("failed to close %s: %w", f.Name(), err)
	}
	res, err := a.inspectSBOMFile(ctx, f.Name())
	if err != nil {
		return res, xerrors.Errorf("SBOM error: %w", err)
	}

	// Found SBOM
	a.logger.Info("Found SBOM in Rekor", log.String("type", string(res.Type)),
		log.String("url", a.artifactOption.RekorURL))

	return res, nil
}

func (a Artifact) inspectSBOMFile(ctx context.Context, filePath string) (artifact.Reference, error) {
	ar, err := sbom.NewArtifact(filePath, a.cache, a.artifactOption)
	if err != nil {
		return artifact.Reference{}, xerrors.Errorf("failed to new artifact: %w", err)
	}

	results, err := ar.Inspect(ctx)
	if err != nil {
		return artifact.Reference{}, xerrors.Errorf("failed to inspect: %w", err)
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
