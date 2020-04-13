package types

import "time"

type DockerOption struct {
	// Auth
	UserName string
	Password string

	// ECR
	AwsAccessKey    string
	AwsSecretKey    string
	AwsSessionToken string
	AwsRegion       string

	// GCP
	GcpCredPath string

	// Docker daemon
	DockerDaemonCertPath string
	DockerDaemonHost     string

	InsecureSkipTLSVerify bool
	NonSSL                bool
	SkipPing              bool // this is ignored now
	Timeout               time.Duration
}
