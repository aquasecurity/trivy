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

type ImageOptions struct {
	RegistryOptions   RegistryOptions
	DockerOptions     DockerOptions
	PodmanOptions     PodmanOptions
	ContainerdOptions ContainerdOptions
}

type DockerOptions struct {
	Host string
}

type PodmanOptions struct {
	// TODO
}

type ContainerdOptions struct {
	// TODO
}

type RegistryOptions struct {
	// Auth for registries
	Credentials []Credential

	// RegistryToken is a bearer token to be sent to a registry
	RegistryToken string

	// SSL/TLS
	Insecure bool

	// Architecture
	Platform Platform

	// ECR
	AWSAccessKey    string
	AWSSecretKey    string
	AWSSessionToken string
	AWSRegion       string

	// GCP
	GCPCredPath string
}

type Credential struct {
	Username string
	Password string
}
