package types

import (
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/samber/lo"
)

const (
	// DockerRuntime is the docker runtime
	DockerRuntime Runtime = "docker"

	// ContainerdRuntime is the containerd runtime
	ContainerdRuntime Runtime = "containerd"

	// PodmanRuntime is the podman runtime
	PodmanRuntime Runtime = "podman"

	// RemoteRuntime represents a remote scan
	RemoteRuntime Runtime = "remote"
)

var (
	AllRuntimes = Runtimes{
		DockerRuntime,
		ContainerdRuntime,
		PodmanRuntime,
		RemoteRuntime,
	}
)

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
	Runtimes          Runtimes
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

// Runtime represents a container runtime
type Runtime string

// Runtimes is a slice of runtimes
type Runtimes []Runtime

type RegistryOptions struct {
	// Auth for registries
	Credentials []Credential

	// RegistryToken is a bearer token to be sent to a registry
	RegistryToken string

	// SSL/TLS
	Insecure bool

	// Architecture
	Platform string

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

func (runtimes Runtimes) StringSlice() []string {
	return lo.Map(runtimes, func(r Runtime, _ int) string {
		return string(r)
	})
}
