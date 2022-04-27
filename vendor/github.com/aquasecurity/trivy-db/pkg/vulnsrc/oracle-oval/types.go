package oracleoval

type OracleOVAL struct {
	Title       string
	Description string
	Platform    []string
	References  []Reference
	Criteria    Criteria
	Severity    string
	Cves        []Cve
}

type Reference struct {
	Source string
	URI    string
	ID     string
}

type Cve struct {
	Impact string
	Href   string
	ID     string
}

type Criteria struct {
	Operator   string
	Criterias  []Criteria
	Criterions []Criterion
}

type Criterion struct {
	Comment string
}

type Package struct {
	Name         string
	FixedVersion string
}

type AffectedPackage struct {
	Package Package
	OSVer   string
}
