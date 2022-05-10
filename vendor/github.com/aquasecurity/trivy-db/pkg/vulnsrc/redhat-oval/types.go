package redhatoval

import "github.com/aquasecurity/trivy-db/pkg/types"

type redhatOVAL struct {
	Class    string
	ID       string
	Version  string
	Metadata ovalMetadata
	Criteria criteria
}

type ovalMetadata struct {
	Title        string
	AffectedList []affected
	References   []reference
	Description  string
	Advisory     ovalAdvisory
}

type ovalAdvisory struct {
	From            string
	Severity        string
	Rights          string
	Issued          issued
	Updated         updated
	Cves            []ovalCVE
	Bugzilla        []bugzilla
	AffectedCpeList []string
}

type criteria struct {
	Operator   string
	Criterias  []criteria
	Criterions []criterion
}

type criterion struct {
	TestRef string
	Comment string
}

type affected struct {
	Family    string
	Platforms []string
}

type reference struct {
	Source string
	RefID  string
	RefURL string
}

type issued struct {
	Date string
}

type updated struct {
	Date string
}

type ovalCVE struct {
	CveID  string
	Cvss2  string
	Cvss3  string
	Cwe    string
	Impact string
	Href   string
	Public string
}

type bugzilla struct {
	ID   string
	Href string
}

type ovalTests struct {
	RpminfoTests []rpminfoTest
}

type ovalObjects struct {
	RpminfoObjects []rpminfoObject
}

type ovalStates struct {
	RpminfoState []rpminfoState
}

type ovalstate struct {
	Text     string
	StateRef string
}

type ovalObject struct {
	Text      string
	ObjectRef string
}

type rpminfoTest struct {
	Check          string
	Comment        string
	ID             string
	Version        string
	CheckExistence string
	Object         ovalObject
	State          ovalstate
}

type rpminfoObject struct {
	ID      string
	Version string
	Name    string
}

type rpminfoState struct {
	ID             string
	Version        string
	Arch           arch
	Evr            evr
	SignatureKeyID signatureKeyID
}

type signatureKeyID struct {
	Text      string
	Operation string
}

type arch struct {
	Text      string
	Datatype  string
	Operation string
}

type evr struct {
	Text      string
	Datatype  string
	Operation string
}

type pkg struct {
	Name         string
	FixedVersion string
}

type bucket struct {
	pkgName string
	vulnID  string
}

type Advisory struct {
	Entries []Entry `json:",omitempty"`
}

type Definition struct {
	Entry Entry `json:",omitempty"`
}

// Entry holds the unique advisory information per platform.
type Entry struct {
	FixedVersion string `json:",omitempty"`
	Cves         []CveEntry

	// For DB size optimization, CPE names will not be stored.
	// CPE indices are stored instead.
	AffectedCPEList    []string `json:"-"`
	AffectedCPEIndices []int    `json:"Affected,omitempty"`
}

type CveEntry struct {
	ID string `json:",omitempty"`

	// Severity may differ depending on platform even though the advisories resolve the same CVE-ID.
	Severity types.Severity `json:",omitempty"`
}
