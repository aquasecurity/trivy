package gradle

import (
	"encoding/xml"
	"fmt"
	"github.com/aquasecurity/trivy/pkg/fanal/log"
	"io"
	"strings"

	"github.com/samber/lo"
	"golang.org/x/net/html/charset"
	"golang.org/x/xerrors"
)

type pomXML struct {
	GroupId      string       `xml:"groupId"`
	ArtifactId   string       `xml:"artifactId"`
	Version      string       `xml:"version"`
	Properties   Properties   `xml:"properties"`
	Dependencies Dependencies `xml:"dependencies"`
	Licenses     Licenses     `xml:"licenses"`
}
type Dependencies struct {
	Text       string       `xml:",chardata"`
	Dependency []Dependency `xml:"dependency"`
}

type Dependency struct {
	Text       string `xml:",chardata"`
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
}

type Licenses struct {
	Text    string    `xml:",chardata"`
	License []License `xml:"license"`
}

type License struct {
	Name string `xml:"name"`
}

type Properties map[string]string

type property struct {
	XMLName xml.Name
	Value   string `xml:",chardata"`
}

func (props *Properties) UnmarshalXML(d *xml.Decoder, _ xml.StartElement) error {
	*props = Properties{}
	for {
		var p property
		err := d.Decode(&p)
		if err == io.EOF {
			break
		} else if err != nil {
			return xerrors.Errorf("XML decode error: %w", err)
		}

		(*props)[p.XMLName.Local] = p.Value
	}
	return nil
}

func parsePom(r io.Reader) (pomXML, error) {
	parsed := pomXML{}
	decoder := xml.NewDecoder(r)
	decoder.CharsetReader = charset.NewReaderLabel
	if err := decoder.Decode(&parsed); err != nil {
		return pomXML{}, xerrors.Errorf("xml decode error: %w", err)
	}
	return parsed, nil
}

func (pom *pomXML) resolveDependencyVersions(path string) {
	for i, dep := range pom.Dependencies.Dependency {
		if strings.HasPrefix(dep.Version, "${") && strings.HasSuffix(dep.Version, "}") {
			dep.Version = strings.TrimPrefix(strings.TrimSuffix(dep.Version, "}"), "${")
			if resolvedVer, ok := pom.Properties[dep.Version]; ok {
				pom.Dependencies.Dependency[i].Version = resolvedVer
			} else if dep.Version == "${project.version}" {
				pom.Dependencies.Dependency[i].Version = dep.Version
			} else {
				// We use simplified logic to resolve properties.
				// If necessary, update and use the logic for maven pom's
				log.Logger.Warnf("Unable to resolve version for %q. Please open a new discussion to update the Trivy logic.", path)
			}
		}
	}
}

func (licenses Licenses) toStringArray() []string {
	if len(licenses.License) == 0 {
		return nil
	}
	return lo.Map(licenses.License, func(license License, _ int) string {
		return license.Name
	})
}

func packageID(groupId, artifactId, ver string) string {
	return fmt.Sprintf("%s:%s:%s", groupId, artifactId, ver)
}
