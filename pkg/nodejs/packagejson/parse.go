package packagejson

import (
	"encoding/json"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"golang.org/x/xerrors"
)

type packageRef struct {
	Type string
	Url  string
}
type packageJSON struct {
	Name       string      `json:"name"`
	Version    string      `json:"version"`
	License    interface{} `json:"license"`
	Homepage   string      `json:"homepage,omitempty"`
	Repository packageRef  `json:"repository,omitempty"`
	Bugs       packageRef  `json:"bugs,omitempty"`
	Funding    packageRef  `json:"funding,omitempty"`
}
type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

func (p *Parser) GetExternalRefs(packageJson packageJSON) []types.ExternalRef {
	externalRefs := []types.ExternalRef{}
	if packageJson.Homepage != "" {
		externalRefs = append(externalRefs, types.ExternalRef{Type: types.RefWebsite, URL: packageJson.Homepage})
	}
	switch v := packageJson.License.(type) {
	case map[string]interface{}:
		if licenseUrl, ok := v["url"]; ok {
			externalRefs = append(externalRefs, types.ExternalRef{Type: types.RefLicense, URL: licenseUrl.(string)})
		}
	}

	if (packageJson.Repository != packageRef{}) {
		externalRefs = append(externalRefs, types.ExternalRef{Type: types.RefVCS, URL: packageJson.Repository.Url})
	}

	if (packageJson.Bugs != packageRef{}) {
		externalRefs = append(externalRefs, types.ExternalRef{Type: types.RefIssueTracker, URL: packageJson.Bugs.Url})
	}

	return externalRefs
}

func (p *Parser) Parse(r dio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	var data packageJSON
	err := json.NewDecoder(r).Decode(&data)
	if err != nil {
		return nil, nil, xerrors.Errorf("JSON decode error: %w", err)
	}

	if data.Name == "" || data.Version == "" {
		return nil, nil, xerrors.Errorf("unable to parse package.json")
	}

	return []types.Library{{
		Name:               data.Name,
		Version:            data.Version,
		License:            parseLicense(data.License),
		ExternalReferences: p.GetExternalRefs(data),
	}}, nil, nil
}

func parseLicense(val interface{}) string {
	// the license isn't always a string, check for legacy struct if not string
	switch v := val.(type) {
	case string:
		return v
	case map[string]interface{}:
		if license, ok := v["type"]; ok {
			return license.(string)
		}
	}
	return ""
}
