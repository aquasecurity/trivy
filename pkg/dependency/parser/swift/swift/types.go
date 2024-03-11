package swift

type LockFile struct {
	Object  Object `json:"object"`
	Pins    []Pin  `json:"pins"`
	Version int    `json:"version"`
}

type Object struct {
	Pins []Pin `json:"pins"`
}

type Pin struct {
	Package       string `json:"package"`
	RepositoryURL string `json:"repositoryURL"` // Package.revision v1
	Location      string `json:"location"`      // Package.revision v2
	State         State  `json:"state"`
	StartLine     int
	EndLine       int
}

type State struct {
	Branch   string `json:"branch"`
	Revision string `json:"revision"`
	Version  string `json:"version"`
}
