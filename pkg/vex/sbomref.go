package vex

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
	"github.com/aquasecurity/trivy/pkg/types"
)

type SBOMReferenceSet struct {
	VEXes []VEX
}

func NewSBOMReferenceSet(report *types.Report) (*SBOMReferenceSet, error) {
	if report.ArtifactType != artifact.TypeCycloneDX {
		return nil, xerrors.Errorf("externalReferences can only be used when scanning CycloneDX SBOMs: %w", report.ArtifactType)
	}

	ctx := log.WithContextPrefix(context.Background(), "vex")
	ctx = log.WithContextAttrs(ctx, log.String("type", "sbom_reference"))

	externalRefs := report.BOM.ExternalReferences()
	urls := parseToURLs(externalRefs)

	v, err := retrieveExternalVEXDocuments(ctx, urls, report)
	if err != nil {
		return nil, xerrors.Errorf("failed to fetch external VEX documents: %w", err)
	} else if v == nil {
		return nil, nil
	}

	return &SBOMReferenceSet{VEXes: v}, nil
}

func parseToURLs(refs []core.ExternalReference) []*url.URL {
	return lo.FilterMap(refs, func(ref core.ExternalReference, _ int) (*url.URL, bool) {
		if ref.Type != core.ExternalReferenceVEX {
			return nil, false
		}
		val, err := url.Parse(ref.URL)
		if err != nil || (val.Scheme != "https" && val.Scheme != "http") {
			// do not concern ourselves with relative URLs at this point
			return nil, false
		}
		return val, true
	})
}

func retrieveExternalVEXDocuments(ctx context.Context, refs []*url.URL, report *types.Report) ([]VEX, error) {
	var docs []VEX
	for _, ref := range refs {
		doc, err := retrieveExternalVEXDocument(ctx, ref, report)
		if err != nil {
			return nil, xerrors.Errorf("failed to retrieve external VEX document: %w", err)
		}
		docs = append(docs, doc)
	}
	log.DebugContext(ctx, "Retrieved external VEX documents", log.Int("count", len(docs)))

	if len(docs) == 0 {
		log.DebugContext(ctx, "No external VEX documents found")
		return nil, nil
	}
	return docs, nil

}

func retrieveExternalVEXDocument(ctx context.Context, vexUrl *url.URL, report *types.Report) (VEX, error) {
	log.DebugContext(ctx, "Retrieving external VEX document", log.String("url", vexUrl.String()))

	res, err := http.Get(vexUrl.String())
	if err != nil {
		return nil, xerrors.Errorf("unable to fetch file via HTTP: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, xerrors.Errorf("did not receive 2xx status code: %w", res.StatusCode)
	}

	val, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, xerrors.Errorf("unable to read response into memory: %w", err)
	}

	v, err := decodeVEX(bytes.NewReader(val), vexUrl.String(), report)
	if err != nil {
		return nil, xerrors.Errorf("unable to load VEX from external reference: %w", err)
	}
	return v, nil
}

func (set *SBOMReferenceSet) NotAffected(vuln types.DetectedVulnerability, product, subComponent *core.Component) (types.ModifiedFinding, bool) {
	for _, vex := range set.VEXes {
		if m, notAffected := vex.NotAffected(vuln, product, subComponent); notAffected {
			return m, notAffected
		}
	}
	return types.ModifiedFinding{}, false
}
