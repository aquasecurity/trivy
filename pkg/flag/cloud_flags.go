package flag

import "github.com/aquasecurity/trivy/pkg/cloud"

var (
	CloudTokenFlag = Flag[string]{
		Name:       "token",
		ConfigName: "cloud.token",
		Usage:      "Token used to athenticate with Trivy Cloud platform",
	}

	CloudApiUrlFlag = Flag[string]{
		Name:       "api-url",
		ConfigName: "cloud.api-url",
		Default:    cloud.DefaultApiUrl,
		Usage:      "API URL for Trivy Cloud platform",
	}

	CloudTrivyServerUrlFlag = Flag[string]{
		Name:       "trivy-server-url",
		ConfigName: "cloud.trivy_server_url",
		Default:    cloud.DefaultTrivyServerUrl,
		Usage:      "Trivy Server URL for Trivy Cloud platform",
	}
)

type CloudFlagGroup struct {
	CloudToken          *Flag[string]
	CloudApiUrl         *Flag[string]
	CloudTrivyServerUrl *Flag[string]
}

func NewCloudFlagGroup() *CloudFlagGroup {
	return &CloudFlagGroup{
		CloudToken:          CloudTokenFlag.Clone(),
		CloudApiUrl:         CloudApiUrlFlag.Clone(),
		CloudTrivyServerUrl: CloudTrivyServerUrlFlag.Clone(),
	}
}

func (f *CloudFlagGroup) Name() string {
	return "Trivy Cloud"
}

func (f *CloudFlagGroup) Flags() []Flagger {
	return []Flagger{
		f.CloudToken,
		f.CloudApiUrl,
		f.CloudTrivyServerUrl,
	}
}

// CloudLoginCredentials is the credentials used to authenticate with Trivy Cloud platform
// In the future this would likely have more information stored for refresh tokens, etc
type CloudLoginCredentials struct {
	Token string
}

type CloudOptions struct {
	LoginCredentials CloudLoginCredentials
	ApiUrl           string
	TrivyServerUrl   string
}

// ToOptions converts the flags to options
func (f *CloudFlagGroup) ToOptions(opts *Options) error {
	opts.CloudOptions = CloudOptions{
		LoginCredentials: CloudLoginCredentials{
			Token: f.CloudToken.Value(),
		},
		ApiUrl:         f.CloudApiUrl.Value(),
		TrivyServerUrl: f.CloudTrivyServerUrl.Value(),
	}
	return nil
}
