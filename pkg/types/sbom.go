package types

type SbomFromType = string

const (
	SbomFromTypeRekor = SbomFromType("rekor")
)

var (
	SbomFroms = []string{
		SbomFromTypeRekor,
	}
)
