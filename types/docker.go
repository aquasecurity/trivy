package types

import "time"

type DockerOption struct {
	AuthURL         string
	UserName        string
	Password        string
	GcpCredPath     string
	AwsAccessKey    string
	AwsSecretKey    string
	AwsSessionToken string
	AwsRegion       string
	Insecure        bool
	Debug           bool
	SkipPing        bool
	NonSSL          bool
	Timeout         time.Duration
}
