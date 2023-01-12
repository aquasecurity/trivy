package types

import v1 "github.com/google/go-containerregistry/pkg/v1"

type Image interface {
	v1.Image
	ImageExtension
}

type ImageExtension interface {
	Name() string
	ID() (string, error)
	RepoTags() []string
	RepoDigests() []string
}
