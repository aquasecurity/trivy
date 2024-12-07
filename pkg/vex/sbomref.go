package vex

import (
	"bytes"
	"fmt"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
	"github.com/aquasecurity/trivy/pkg/types"
	"golang.org/x/xerrors"
	"io"
	"net/http"
	"net/url"
)

type SBOMReferenceSet struct {
	Vexes []VEX
}

func NewSBOMReferenceSet(report *types.Report) (*SBOMReferenceSet, error) {
	fmt.Println("hello there")

	if report.ArtifactType != artifact.TypeCycloneDX {
		return nil, xerrors.Errorf("externalReferences can only be used when scanning CycloneDX SBOMs: %w", report.ArtifactType)
	}

	var externalRefs = report.BOM.ExternalReferences()
	urls := ParseToURLs(externalRefs)

	v, err := RetrieveExternalVEXDocuments(urls, report)
	if err != nil {
		return nil, xerrors.Errorf("failed to fetch external VEX document: %w", err)
	}

	return &SBOMReferenceSet{Vexes: v}, nil
}

func ParseToURLs(refs []core.ExternalReference) []url.URL {
	var urls []url.URL
	for _, ref := range refs {
		if ref.Type == core.ExternalReferenceVex {
			val, err := url.Parse(ref.URL)
			// do not concern ourselves with relative URLs at this point
			if err != nil || (val.Scheme != "https" && val.Scheme != "http") {
				continue
			}
			urls = append(urls, *val)
		}
	}
	return urls
}

func RetrieveExternalVEXDocuments(refs []url.URL, report *types.Report) ([]VEX, error) {

	logger := log.WithPrefix("vex").With(log.String("type", "externalReference"))

	var docs []VEX
	for _, ref := range refs {
		doc, err := RetrieveExternalVEXDocument(ref, report)
		if err != nil && doc != nil {
			docs = append(docs, doc)
		}
	}
	logger.Debug("Retrieved external VEX documents", "count", len(docs))

	if len(docs) == 0 {
		logger.Info("No external VEX documents found")
		return nil, nil
	}
	return docs, nil

}

func RetrieveExternalVEXDocument(VEXUrl url.URL, report *types.Report) (VEX, error) {

	logger := log.WithPrefix("vex").With(log.String("type", "externalReference"))

	logger.Info(fmt.Sprintf("Retrieving external VEX document from host %s", VEXUrl.Host))

	res, err := http.Get(VEXUrl.String())
	if err != nil {
		return nil, xerrors.Errorf("unable to fetch file via HTTP: %w", err)
	}
	defer res.Body.Close()

	val, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, xerrors.Errorf("unable to read response into memory: %w", err)
	}

	if v, err := decodeVEX(bytes.NewReader(val), VEXUrl.String(), report); err != nil {
		return nil, xerrors.Errorf("unable to load VEX: %w", err)
	} else {
		return v, nil
	}
}

func (set *SBOMReferenceSet) NotAffected(vuln types.DetectedVulnerability, product, subComponent *core.Component) (types.ModifiedFinding, bool) {

	for _, vex := range set.Vexes {
		if m, notAffected := vex.NotAffected(vuln, product, subComponent); notAffected {
			return m, notAffected
		}
	}
	return types.ModifiedFinding{}, false
}
