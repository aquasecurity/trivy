package gradle

import (
	"encoding/xml"
	"golang.org/x/net/html/charset"
	"golang.org/x/xerrors"
	"io"
)

type pomXML struct {
	GroupId    string      `xml:"groupId"`
	ArtifactId string      `xml:"artifactId"`
	Version    string      `xml:"version"`
	Licenses   pomLicenses `xml:"licenses"`
}

type pomLicenses struct {
	Text    string       `xml:",chardata"`
	License []pomLicense `xml:"license"`
}

type pomLicense struct {
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
