package ubuntu

type UbuntuCVE struct {
	Description string `json:"description"`
	Candidate   string
	Priority    string
	Patches     map[PackageName]Patch
	References  []string
}

type PackageName string
type Release string
type Patch map[Release]Status

type Status struct {
	Status string
	Note   string
}
