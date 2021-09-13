package types

import v1 "github.com/google/go-containerregistry/pkg/v1"

type Image interface {
	v1.Image
	Name() string
	ID() (string, error)
	LayerIDs() ([]string, error)
	RepoTags() []string
	RepoDigests() []string
}
