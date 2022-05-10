package susecvrf

type SuseCvrf struct {
	Title           string           `xml:"DocumentTitle"`
	Tracking        DocumentTracking `xml:"DocumentTracking"`
	Notes           []DocumentNote   `xml:"DocumentNotes>Note"`
	ProductTree     ProductTree      `xml:"ProductTree"`
	References      []Reference      `xml:"DocumentReferences>Reference"`
	Vulnerabilities []Vulnerability  `xml:"Vulnerability"`
}

type DocumentTracking struct {
	ID                 string     `xml:"Identification>ID"`
	Status             string     `xml:"Status"`
	Version            string     `xml:"Version"`
	InitialReleaseDate string     `xml:"InitialReleaseDate"`
	CurrentReleaseDate string     `xml:"CurrentReleaseDate"`
	RevisionHistory    []Revision `xml:"RevisionHistory>Revision"`
}

type DocumentNote struct {
	Text  string `xml:",chardata"`
	Title string `xml:"Title,attr"`
	Type  string `xml:"Type,attr"`
}

type ProductTree struct {
	Relationships []Relationship `xml:"Relationship"`
}

type Relationship struct {
	ProductReference          string `xml:"ProductReference,attr"`
	RelatesToProductReference string `xml:"RelatesToProductReference,attr"`
	RelationType              string `xml:"RelationType,attr"`
}

type Revision struct {
	Number      string `xml:"Number"`
	Date        string `xml:"Date"`
	Description string `xml:"Description"`
}

type Vulnerability struct {
	CVE             string      `xml:"CVE"`
	Description     string      `xml:"Notes>Note"`
	Threats         []Threat    `xml:"Threats>Threat"`
	References      []Reference `xml:"References>Reference"`
	ProductStatuses []Status    `xml:"ProductStatuses>Status"`
	CVSSScoreSets   ScoreSet    `xml:"CVSSScoreSets>ScoreSet" json:",omitempty"`
}

type Threat struct {
	Type     string `xml:"Type,attr"`
	Severity string `xml:"Description"`
}

type Reference struct {
	URL         string `xml:"URL"`
	Description string `xml:"Description"`
}

type Status struct {
	Type      string   `xml:"Type,attr"`
	ProductID []string `xml:"ProductID"`
}

type ScoreSet struct {
	BaseScore string `xml:"BaseScore" json:",omitempty"`
	Vector    string `xml:"Vector" json:",omitempty"`
}

type Package struct {
	Name         string
	FixedVersion string
}

type AffectedPackage struct {
	Package Package
	OSVer   string
}
