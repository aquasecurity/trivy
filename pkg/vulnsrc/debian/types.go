package debian

type DebianCVE struct {
	Description     string             `json:"description"`
	Releases        map[string]Release `json:"releases"`
	Scope           string             `json:"scope"`
	Package         string
	VulnerabilityID string
}

type Release struct {
	Repositories map[string]string `json:"repositories"`
	Status       string            `json:"status"`
	Urgency      string            `json:"urgency"`
}
