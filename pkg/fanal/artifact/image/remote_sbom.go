package image

import (
	"bytes"
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

	client, err := rekor.NewClient(a.artifactOption.RekorURL)
	if err != nil {
		return ftypes.ArtifactReference{}, xerrors.Errorf("failed to create rekor client: %w", err)
	}

	entryIDs, err := client.Search(ctx, digest)
	if err != nil {
		return ftypes.ArtifactReference{}, xerrors.Errorf("failed to search rekor records: %w", err)
	} else if len(entryIDs) == 0 {
		return ftypes.ArtifactReference{}, errNoSBOMFound
	}

	log.Logger.Debugf("Found matching Rekor entries: %s", entryIDs)

	for i := 0; i < len(entryIDs); i += rekor.MaxGetEntriesLimit {
		end := i + rekor.MaxGetEntriesLimit
		if end > len(entryIDs) {
			end = len(entryIDs)
		}

		entries, err := client.GetEntries(ctx, entryIDs[i:end])
		if err != nil {
			return ftypes.ArtifactReference{}, xerrors.Errorf("failed to get entries: %w", err)
		}

		for _, entry := range entries {
			ref, err := a.inspectRekorRecord(ctx, entry)
			if errors.Is(err, errNoSBOMFound) {
				continue
			} else if err != nil {
				return ftypes.ArtifactReference{}, xerrors.Errorf("rekor record inspection error: %w", err)
			}
			return ref, nil
		}
	}
	return ftypes.ArtifactReference{}, errNoSBOMFound
}

func (a Artifact) inspectRekorRecord(ctx context.Context, entry rekor.Entry) (ftypes.ArtifactReference, error) {

	// TODO: Trivy SBOM should take precedence
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
	// Skip base64-encoded attestation
	if bytes.HasPrefix(entry.Statement, []byte(`eyJ`)) {
		return nil, errNoSBOMFound
	}

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
		return nil, xerrors.Errorf("unsupported predicate type %s: %w", statement.PredicateType, errNoSBOMFound)
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
	return "", xerrors.Errorf("no repo digest found: %w", errNoSBOMFound)

}
