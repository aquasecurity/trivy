package image

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"

	"github.com/in-toto/in-toto-golang/in_toto"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/attestation"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact/sbom"
	"github.com/aquasecurity/trivy/pkg/fanal/log"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/rekor"
	"github.com/aquasecurity/trivy/pkg/types"
)

var (
	errSBOMNotFound = xerrors.New("remote SBOM not found")
	errNoRepoDigest = xerrors.New("no repo digest")
)

func (a Artifact) fetchRemoteSBOM(ctx context.Context) (ftypes.ArtifactReference, error) {
	for _, sbomFrom := range a.artifactOption.SbomFroms {
		switch sbomFrom {
		case types.SbomFromTypeRekor:
			ref, err := a.inspectSbomAttestation(ctx)
			if err == nil {
				return ref, nil
			}
			log.Logger.Debugf("Failed to inspect SBOM Attestation from rekor")
		}
	}
	return ftypes.ArtifactReference{}, errSBOMNotFound

}

func (a Artifact) inspectSbomAttestation(ctx context.Context) (ftypes.ArtifactReference, error) {
	digest, err := repoDigest(a.image)
	if err != nil {
		return ftypes.ArtifactReference{}, xerrors.Errorf("failed to get repo digest: %w", err)
	}

	client, err := rekor.NewClient(a.artifactOption.RekorUrl)
	if err != nil {
		return ftypes.ArtifactReference{}, xerrors.Errorf("failed to create rekor client: %w", err)
	}

	entryIDs, err := client.Search(ctx, digest)
	if err != nil {
		if errors.Is(err, rekor.ErrNoEntry) {
			return ftypes.ArtifactReference{}, errSBOMNotFound
		}
		return ftypes.ArtifactReference{}, xerrors.Errorf("failed to search rekor records: %w", err)
	}

	log.Logger.Debugf("Found matching Rekor entries: %s", entryIDs)
	for _, id := range entryIDs {
		log.Logger.Debugf("Inspecting Rekor entry: %s", id)
		results, err := a.inspectRekorRecord(ctx, client, id)
		if err != nil {
			if errors.Is(err, errSBOMNotFound) {
				continue
			}
			return ftypes.ArtifactReference{}, xerrors.Errorf("rekor rekord inspection error: %w", err)
		}
		// Found SBOM
		return results, nil
	}
	return ftypes.ArtifactReference{}, xerrors.Errorf("failed to inspect SBOM attestation: %w", err)
}

func (a Artifact) inspectRekorRecord(ctx context.Context, client *rekor.Client, entryID rekor.EntryID) (ftypes.ArtifactReference, error) {
	entry, err := client.GetEntry(ctx, entryID)
	if err != nil {
		if errors.Is(err, rekor.ErrNoEntry) || errors.Is(err, rekor.ErrNoAttestation) {
			return ftypes.ArtifactReference{}, errSBOMNotFound
		}
		return ftypes.ArtifactReference{}, xerrors.Errorf("failed to get rekor entry: %w", err)
	}

	raw, err := a.parseStatement(entry)
	if err != nil {
		return ftypes.ArtifactReference{}, err
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

func (a Artifact) parseStatement(entry rekor.Entry) (json.RawMessage, error) {
	// Parse statement of in-toto attestation
	var raw json.RawMessage
	statement := &in_toto.Statement{
		Predicate: &attestation.CosignPredicate{
			Data: &raw, // Extract CycloneDX or SPDX
		},
	}
	if err := json.Unmarshal(entry.Statement, &statement); err != nil {
		return nil, xerrors.Errorf("attestation parse error: %w", err)
	}

	// TODO: add support for SPDX
	if statement.PredicateType != in_toto.PredicateCycloneDX {
		return nil, xerrors.Errorf("unsupported predicate type %s: %w", statement.PredicateType, errSBOMNotFound)
	}
	return raw, nil
}

func repoDigest(img ftypes.Image) (string, error) {
	repoNameFull := img.Name()
	repoName, _, _ := strings.Cut(repoNameFull, ":")

	for _, rd := range img.RepoDigests() {
		if name, d, found := strings.Cut(rd, "@"); found && name == repoName {
			return d, nil
		}
	}
	return "", errNoRepoDigest

}
