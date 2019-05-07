package alpine

type AlpineCVE struct {
	VulnerabilityID string
	Release         string
	Package         string
	Repository      string
	FixedVersion    string
	Subject         string
	Description     string
}

type Advisory struct {
	VulnerabilityID string
	FixedVersion    string
	Repository      string
}
