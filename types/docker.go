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

	SkipPing              bool
	InsecureSkipTLSVerify bool
	Timeout               time.Duration
}
