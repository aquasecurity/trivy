package oval

////////////////////////
//  definitions.json  //
////////////////////////
type Definition struct {
	Class    string
	ID       string
	Version  string
	Metadata Metadata
	Criteria Criteria
}

type Criteria struct {
	Operator  string
	Criterion Criterion
}

type Criterion struct {
	Comment string
	TestRef string
}

type Metadata struct {
	Title        string
	Affected     Affected
	Reference    Reference
	Patchable    bool `json:",string"`
	AdvisoryDate string
	AdvisoryID   string
	Severity     string
	Description  string
}

type Reference struct {
	RefID  string
	RefURL string
	Source string
}

type Affected struct {
	Family   string
	Platform string
}

type State struct {
	StateRef string
}

type Object struct {
	ObjectRef string
}

////////////////
// tests.json //
////////////////
type Tests struct {
	RpminfoTests []RpmInfoTest
}

type RpmInfoTest struct {
	Check   string
	Comment string
	ID      string
	Version string
	Object  Object
	State   State
}

//////////////////
// objects.json //
//////////////////
type Objects struct {
	RpminfoObjects []RpmInfoObject
}

type RpmInfoObject struct {
	ID      string
	Version string
	Name    string
}

/////////////////
// states.json //
/////////////////
type States struct {
	RpminfoState []RpmInfoState
}

type RpmInfoState struct {
	ID      string
	Version string
	Evr     Evr
}

type Evr struct {
	Text      string
	Datatype  string
	Operation string
}
