package types

import (
	"encoding/json"

	"github.com/package-url/packageurl-go"
	"golang.org/x/xerrors"
)

type PackageURL struct {
	packageurl.PackageURL
	FilePath string
}

func (p *PackageURL) BOMRef() string {
	// 'bom-ref' must be unique within BOM, but PURLs may conflict
	// when the same packages are installed in an artifact.
	// In that case, we prefer to make PURLs unique by adding file paths,
	// rather than using UUIDs, even if it is not PURL technically.
	// ref. https://cyclonedx.org/use-cases/#dependency-graph
	purl := p.PackageURL // so that it will not override the qualifiers below
	if p.FilePath != "" {
		purl.Qualifiers = append(purl.Qualifiers,
			packageurl.Qualifier{
				Key:   "file_path",
				Value: p.FilePath,
			},
		)
	}
	return purl.String()
}

func (p *PackageURL) MarshalJSON() ([]byte, error) {
	if p == nil {
		return nil, nil
	}
	return json.Marshal(p.String())
}

func (p *PackageURL) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	purl, err := NewPackageURL(s)
	if err != nil {
		return xerrors.Errorf("failed to parse purl(%s): %w", string(b), err)
	}
	*p = *purl
	return nil
}

func NewPackageURL(s string) (*PackageURL, error) {
	p, err := packageurl.FromString(s)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse purl(%s): %w", s, err)
	}

	// Take out and delete the file path from qualifiers
	var filePath string
	for i, q := range p.Qualifiers {
		if q.Key != "file_path" {
			continue
		}
		filePath = q.Value
		p.Qualifiers = append(p.Qualifiers[:i], p.Qualifiers[i+1:]...)
		break
	}

	if len(p.Qualifiers) == 0 {
		p.Qualifiers = nil
	}

	return &PackageURL{
		PackageURL: p,
		FilePath:   filePath,
	}, nil
}
