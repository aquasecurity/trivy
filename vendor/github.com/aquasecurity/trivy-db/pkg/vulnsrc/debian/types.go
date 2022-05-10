package debian

type Advisory struct {
	VulnerabilityID string
	Platform        string
	PkgName         string

	VendorIDs    []string
	State        string
	Severity     string
	FixedVersion string
}

type bucket struct {
	codeName string
	pkgName  string
	vulnID   string // CVE-ID, DLA-ID or DSA-ID
	severity string
}

type header struct {
	ID          string `json:"ID"`
	Description string `json:"Description"`
}

type annotation struct {
	Type        string
	Release     string
	Package     string
	Kind        string
	Version     string
	Description string
	Severity    string
	Bugs        []string
}

type bug struct {
	Header      header
	Annotations []annotation
}
