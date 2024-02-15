package gradle

import (
	"encoding/xml"
	"io"

	"golang.org/x/net/html/charset"
	"golang.org/x/xerrors"
)

type pomXML struct {
	GroupId      string       `xml:"groupId"`
	ArtifactId   string       `xml:"artifactId"`
	Version      string       `xml:"version"`
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

func parsePom(r io.Reader) (pomXML, error) {
	parsed := pomXML{}
	decoder := xml.NewDecoder(r)
	decoder.CharsetReader = charset.NewReaderLabel
	if err := decoder.Decode(&parsed); err != nil {
		return pomXML{}, xerrors.Errorf("xml decode error: %w", err)
	}
	return parsed, nil
}
