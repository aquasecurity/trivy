package sbom

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/attestation"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/rekor"
)

var ErrNoSBOMAttestation = xerrors.New("no SBOM attestation found")

type Rekor struct {
	client *rekor.Client
}

func NewRekor(url string) (Rekor, error) {
	c, err := rekor.NewClient(url)
	if err != nil {
		return Rekor{}, xerrors.Errorf("rekor client error: %w", err)
	}
	return Rekor{
		client: c,
	}, nil
}

func (r *Rekor) RetrieveSBOM(ctx context.Context, digest string) ([]byte, error) {
	entryIDs, err := r.client.Search(ctx, digest)
	if err != nil {
		return nil, xerrors.Errorf("failed to search rekor records: %w", err)
	} else if len(entryIDs) == 0 {
		return nil, ErrNoSBOMAttestation
	}

	log.Logger.Debugf("Found matching Rekor entries: %s", entryIDs)

	for _, ids := range lo.Chunk[rekor.EntryID](entryIDs, rekor.MaxGetEntriesLimit) {
		entries, err := r.client.GetEntries(ctx, ids)
		if err != nil {
			return nil, xerrors.Errorf("failed to get entries: %w", err)
		}

		for _, entry := range entries {
			ref, err := r.inspectRecord(entry)
			if errors.Is(err, ErrNoSBOMAttestation) {
				continue
			} else if err != nil {
				return nil, xerrors.Errorf("rekor record inspection error: %w", err)
			}
			return ref, nil
		}
	}
	return nil, ErrNoSBOMAttestation
}

func (r *Rekor) inspectRecord(entry rekor.Entry) ([]byte, error) {
	// TODO: Trivy SBOM should take precedence
	raw, err := r.parseStatement(entry)
	if err != nil {
		return nil, err
	}
	return raw, nil
}

func (r *Rekor) parseStatement(entry rekor.Entry) (json.RawMessage, error) {
	// Skip base64-encoded attestation
	if bytes.HasPrefix(entry.Statement, []byte(`eyJ`)) {
		return nil, ErrNoSBOMAttestation
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
		return nil, xerrors.Errorf("unsupported predicate type %s: %w", statement.PredicateType, ErrNoSBOMAttestation)
	}
	return raw, nil
}
