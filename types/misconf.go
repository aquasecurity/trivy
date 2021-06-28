package types

type Misconfiguration struct {
	FileType   string         `json:",omitempty"`
	FilePath   string         `json:",omitempty"`
	Successes  MisconfResults `json:",omitempty"`
	Warnings   MisconfResults `json:",omitempty"`
	Failures   MisconfResults `json:",omitempty"`
	Exceptions MisconfResults `json:",omitempty"`
	Layer      Layer          `json:",omitempty"`
}

type MisconfResult struct {
	Namespace      string `json:",omitempty"`
	Message        string `json:",omitempty"`
	PolicyMetadata `json:",omitempty"`
}

type MisconfResults []MisconfResult

type PolicyMetadata struct {
	ID       string `json:",omitempty"`
	Type     string `json:",omitempty"`
	Title    string `json:",omitempty"`
	Severity string `json:",omitempty"`
}

type PolicyInputOption struct {
	Combine   bool                  `mapstructure:"combine"`
	Selectors []PolicyInputSelector `mapstructure:"selector"`
}

type PolicyInputSelector struct {
	Type string `mapstructure:"type"`
}

func (r MisconfResults) Len() int {
	return len(r)
}

func (r MisconfResults) Swap(i, j int) {
	r[i], r[j] = r[j], r[i]
}

func (r MisconfResults) Less(i, j int) bool {
	switch {
	case r[i].Type != r[j].Type:
		return r[i].Type < r[j].Type
	case r[i].ID != r[j].ID:
		return r[i].ID < r[j].ID
	case r[i].Severity != r[j].Severity:
		return r[i].Severity < r[j].Severity
	}
	return r[i].Message < r[j].Message
}
