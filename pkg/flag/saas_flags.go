package flag

var (
	SaasTokenFlag = Flag[string]{
		Name:       "token",
		ConfigName: "saas.token",
		Usage:      "Token used to athenticate with Trivy Cloud platform",
	}

	SaasApiUrlFlag = Flag[string]{
		Name:       "api-url",
		ConfigName: "saas.api_url",
		Default:    "https://app.trivy.dev",
		Usage:      "API URL for Trivy Cloud platform",
	}

	SaasTrivyServerUrlFlag = Flag[string]{
		Name:       "trivy-server-url",
		ConfigName: "saas.trivy_server_url",
		Default:    "https://scan.trivy.dev",
		Usage:      "Trivy Server URL for Trivy Cloud platform",
	}
)

type SaasFlagGroup struct {
	SaasToken          *Flag[string]
	SaasApiUrl         *Flag[string]
	SaasTrivyServerUrl *Flag[string]
}

func NewSaasFlagGroup() *SaasFlagGroup {
	return &SaasFlagGroup{
		SaasToken:          SaasTokenFlag.Clone(),
		SaasApiUrl:         SaasApiUrlFlag.Clone(),
		SaasTrivyServerUrl: SaasTrivyServerUrlFlag.Clone(),
	}
}

func (f *SaasFlagGroup) Name() string {
	return "Trivy Cloud"
}

func (f *SaasFlagGroup) Flags() []Flagger {
	return []Flagger{
		f.SaasToken,
		f.SaasApiUrl,
		f.SaasTrivyServerUrl,
	}
}

// SaasCredentials is the credentials used to authenticate with Trivy Cloud platform
// In the future this would likely have more information stored for refresh tokens, etc
type SaasCredentials struct {
	Token string
}

type SaasOptions struct {
	SaasCredentials    SaasCredentials
	SaasApiUrl         string
	SaasTrivyServerUrl string
}

// ToOptions converts the flags to options
func (f *SaasFlagGroup) ToOptions(opts *Options) error {
	opts.SaasOptions = SaasOptions{
		SaasCredentials: SaasCredentials{
			Token: f.SaasToken.Value(),
		},
		SaasApiUrl:         f.SaasApiUrl.Value(),
		SaasTrivyServerUrl: f.SaasTrivyServerUrl.Value(),
	}
	return nil
}
