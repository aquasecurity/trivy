package debianoval

type DebianOVAL struct {
	Metadata Metadata
	Criteria Criteria
	Release  string
}

type Metadata struct {
	Title        string
	AffectedList []Affected
	Description  string
	References   []Reference
}

type Affected struct {
	Family   string
	Platform string
	Product  string
}

type Criteria struct {
	Operator   string
	Criterias  []Criteria
	Criterions []Criterion
}

type Reference struct {
	Source string
	RefID  string
	RefURL string
}

type Criterion struct {
	Negate  bool
	TestRef string
	Comment string
}

type Package struct {
	Name         string
	FixedVersion string
}
