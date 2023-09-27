package types

import (
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

const (
	// DockerImageSource is the docker runtime
	DockerImageSource ImageSource = "docker"

	// ContainerdImageSource is the containerd runtime
	ContainerdImageSource ImageSource = "containerd"

	// PodmanImageSource is the podman runtime
	PodmanImageSource ImageSource = "podman"

	// RemoteImageSource represents a remote scan
	RemoteImageSource ImageSource = "remote"
)

var (
	AllImageSources = ImageSources{
		DockerImageSource,
		ContainerdImageSource,
		PodmanImageSource,
		RemoteImageSource,
	}
)

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
	ImageSources      ImageSources
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

// ImageSource represents the source of an image. It can be a string that identifies
// the container registry or a type of container runtime.
type ImageSource string

// ImageSources is a slice of image sources
type ImageSources []ImageSource

type RegistryOptions struct {
	// Auth for registries
	Credentials []Credential

	// RegistryToken is a bearer token to be sent to a registry
	RegistryToken string

	// SSL/TLS
	Insecure bool

	// For internal use. Needed for mTLS authentication.
	ClientCert []byte
	ClientKey  []byte

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
