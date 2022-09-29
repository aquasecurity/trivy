package types

type SBOMSource = string

const (
	SBOMSourceRekor = SBOMSource("rekor")
)

var (
	SBOMSources = []string{
		SBOMSourceRekor,
	}
)
