package types

import v1 "github.com/google/go-containerregistry/pkg/v1"

type Platform struct {
	*v1.Platform

	// Force returns an error if the specified platform is not found.
	// This option is for Aqua, and cannot be configured via Trivy CLI.
	Force bool
}

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
