package image

import (
	"context"
	"errors"
	"os"
	"strings"

	"golang.org/x/xerrors"

	sbomatt "github.com/aquasecurity/trivy/pkg/attestation/sbom"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact/sbom"
	"github.com/aquasecurity/trivy/pkg/fanal/log"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

var errNoSBOMFound = xerrors.New("remote SBOM not found")

func (a Artifact) retrieveRemoteSBOM(ctx context.Context) (ftypes.ArtifactReference, error) {
	for _, sbomFrom := range a.artifactOption.SBOMSources {
		switch sbomFrom {
		case types.SBOMSourceRekor:
			ref, err := a.inspectSBOMAttestation(ctx)
			if errors.Is(err, errNoSBOMFound) {
				// Try the next SBOM source
				continue
			} else if err != nil {
				return ftypes.ArtifactReference{}, xerrors.Errorf("Rekor attestation searching error: %w", err)
			}
			// Found SBOM
			log.Logger.Infof("Found SBOM (%s) attestation in Rekor", ref.Type)
			return ref, nil
		}
	}
	return ftypes.ArtifactReference{}, errNoSBOMFound
}

func (a Artifact) inspectSBOMAttestation(ctx context.Context) (ftypes.ArtifactReference, error) {
	digest, err := repoDigest(a.image)
	if err != nil {
		return ftypes.ArtifactReference{}, xerrors.Errorf("repo digest error: %w", err)
	}

	client, err := sbomatt.NewRekor(a.artifactOption.RekorURL)
	if err != nil {
		return ftypes.ArtifactReference{}, xerrors.Errorf("failed to create rekor client: %w", err)
	}

	raw, err := client.RetrieveSBOM(ctx, digest)
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
		return ftypes.ArtifactReference{}, xerrors.Errorf("failed to write statement: %w", err)
	}
	if err = f.Close(); err != nil {
		return ftypes.ArtifactReference{}, xerrors.Errorf("failed to close %s: %w", f.Name(), err)
	}

	ar, err := sbom.NewArtifact(f.Name(), a.cache, a.artifactOption)
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

func repoDigest(img ftypes.Image) (string, error) {
	repoNameFull := img.Name()
	repoName, _, _ := strings.Cut(repoNameFull, ":")

	for _, rd := range img.RepoDigests() {
		if name, d, found := strings.Cut(rd, "@"); found && name == repoName {
			return d, nil
		}
	}
	return "", xerrors.Errorf("no repo digest found: %w", errNoSBOMFound)

}
