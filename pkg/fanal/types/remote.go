package types

type RemoteOptions struct {
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
