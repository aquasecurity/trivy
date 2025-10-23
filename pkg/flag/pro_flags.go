package flag

const (
	DefaultApiURL         = "https://api.trivy.dev"
	DefaultTrivyServerURL = "https://scan.trivy.dev"
)

var (
	ProTokenFlag = Flag[string]{
		Name:       "pro-token",
		ConfigName: "pro.token",
		Usage:      "Token used to athenticate with Trivy Pro platform",
	}

	ProAPIURLFlag = Flag[string]{
		Name:          "pro-api-url",
		ConfigName:    "pro.api-url",
		Default:       DefaultApiURL,
		Usage:         "API URL for Trivy Pro platform, requires the token to be provided to have an effect",
		TelemetrySafe: true,
	}

	ProAppURLFlag = Flag[string]{
		Name:          "pro-app-url",
		ConfigName:    "pro.app-url",
		Default:       "https://app.trivy.dev",
		Usage:         "App URL for Trivy Pro platform, requires the token to be provided to have an effect",
		TelemetrySafe: true,
	}

	ProTrivyServerURLFlag = Flag[string]{
		Name:          "pro-trivy-server-url",
		ConfigName:    "pro.trivy-server-url",
		Default:       DefaultTrivyServerURL,
		Usage:         "Trivy Server URL for Trivy Pro platform, requires the token to be provided to have an effect",
		TelemetrySafe: true,
	}

	ProUploadResultsFlag = Flag[bool]{
		Name:          "pro-upload-results",
		ConfigName:    "pro.upload-results",
		Default:       false,
		Usage:         "Upload results to Trivy Pro platform, requires the token to be provided to have an effect",
		TelemetrySafe: true,
	}

	ProSecretConfigFlag = Flag[bool]{
		Name:          "pro-use-secret-config",
		ConfigName:    "pro.use-secret-config",
		Default:       true,
		Usage:         "Use secret configurations from Trivy Pro platform, requires the token to be provided to have an effect",
		TelemetrySafe: true,
	}

	ProUseServerSideScanningFlag = Flag[bool]{
		Name:          "pro-server-scanning",
		ConfigName:    "pro.server-scanning",
		Default:       true,
		Usage:         "Use server-side image scanning in Trivy Pro platform, requires the token to be provided to have an effect",
		TelemetrySafe: true,
	}
)

type ProFlagGroup struct {
	ProToken          *Flag[string]
	ProApiURL         *Flag[string]
	ProAppURL         *Flag[string]
	ProTrivyServerURL *Flag[string]
	ProUploadResults  *Flag[bool]
	ProSecretConfig   *Flag[bool]

	ProUseServerSideScanning *Flag[bool]
}

func NewProFlagGroup() *ProFlagGroup {
	return &ProFlagGroup{
		ProToken:                 ProTokenFlag.Clone(),
		ProApiURL:                ProAPIURLFlag.Clone(),
		ProAppURL:                ProAppURLFlag.Clone(),
		ProTrivyServerURL:        ProTrivyServerURLFlag.Clone(),
		ProUploadResults:         ProUploadResultsFlag.Clone(),
		ProSecretConfig:          ProSecretConfigFlag.Clone(),
		ProUseServerSideScanning: ProUseServerSideScanningFlag.Clone(),
	}
}

func (f *ProFlagGroup) Name() string {
	return "Trivy Pro"
}

func (f *ProFlagGroup) Flags() []Flagger {
	return []Flagger{
		f.ProToken,
		f.ProApiURL,
		f.ProAppURL,
		f.ProTrivyServerURL,
		f.ProUploadResults,
		f.ProSecretConfig,
		f.ProUseServerSideScanning,
	}
}

// ProLoginCredentials is the credentials used to authenticate with Trivy Pro platform
// In the future this would likely have more information stored for refresh tokens, etc
type ProLoginCredentials struct {
	Token string
}

type ProOptions struct {
	ProToken              string
	ApiURL                string
	AppURL                string
	TrivyServerURL        string
	UploadResults         bool
	SecretConfig          bool
	UseServerSideScanning bool
}

// ToOptions converts the flags to options
func (f *ProFlagGroup) ToOptions(opts *Options) error {
	opts.ProOptions = ProOptions{
		ProToken:              f.ProToken.Value(),
		ApiURL:                f.ProApiURL.Value(),
		AppURL:                f.ProAppURL.Value(),
		TrivyServerURL:        f.ProTrivyServerURL.Value(),
		UploadResults:         f.ProUploadResults.Value(),
		SecretConfig:          f.ProSecretConfig.Value(),
		UseServerSideScanning: f.ProUseServerSideScanning.Value(),
	}
	return nil
}
