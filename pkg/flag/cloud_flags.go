package flag

const (
	DefaultApiURL         = "https://api.trivy.dev"
	DefaultTrivyServerURL = "https://scan.trivy.dev"
)

var (
	CloudTokenFlag = Flag[string]{
		Name:       "cloud-token",
		ConfigName: "cloud.cloud-token",
		Usage:      "Token used to athenticate with Trivy Cloud platform",
	}

	CloudApiURLFlag = Flag[string]{
		Name:          "cloud-api-url",
		ConfigName:    "cloud.api-url",
		Default:       DefaultApiURL,
		Usage:         "API URL for Trivy Cloud platform",
		TelemetrySafe: true,
	}

	CloudTrivyServerURLFlag = Flag[string]{
		Name:          "cloud-trivy-server-url",
		ConfigName:    "cloud.trivy-server-url",
		Default:       DefaultTrivyServerURL,
		Usage:         "Trivy Server URL for Trivy Cloud platform",
		TelemetrySafe: true,
	}

	CloudUploadResultsFlag = Flag[bool]{
		Name:          "cloud-upload-results",
		ConfigName:    "cloud.upload-results",
		Default:       true,
		Usage:         "Upload results to Trivy Cloud platform",
		TelemetrySafe: true,
	}

	CloudSecretConfigFlag = Flag[bool]{
		Name:          "cloud-download-secret-config",
		ConfigName:    "cloud.download-secret-config",
		Default:       true,
		Usage:         "Download secret configurations from Trivy Cloud platform",
		TelemetrySafe: true,
	}

	CloudMisconfigConfigFlag = Flag[bool]{
		Name:          "cloud-download-misconfig-config",
		ConfigName:    "cloud.download-misconfig-config",
		Default:       true,
		Usage:         "Download misconfig configurations from Trivy Cloud platform",
		TelemetrySafe: true,
	}

	CloudUseServerSideScanningFlag = Flag[bool]{
		Name:          "cloud-server-scanning",
		ConfigName:    "cloud.server-scanning",
		Default:       true,
		Usage:         "Use server-side image scanning in Trivy Cloud platform",
		TelemetrySafe: true,
	}
)

type CloudFlagGroup struct {
	CloudToken                 *Flag[string]
	CloudApiURL                *Flag[string]
	CloudTrivyServerURL        *Flag[string]
	CloudUploadResults         *Flag[bool]
	CloudSecretConfig          *Flag[bool]
	CloudMisconfigConfig       *Flag[bool]
	CloudUseServerSideScanning *Flag[bool]
}

func NewCloudFlagGroup() *CloudFlagGroup {
	return &CloudFlagGroup{
		CloudToken:                 CloudTokenFlag.Clone(),
		CloudApiURL:                CloudApiURLFlag.Clone(),
		CloudTrivyServerURL:        CloudTrivyServerURLFlag.Clone(),
		CloudUploadResults:         CloudUploadResultsFlag.Clone(),
		CloudSecretConfig:          CloudSecretConfigFlag.Clone(),
		CloudMisconfigConfig:       CloudMisconfigConfigFlag.Clone(),
		CloudUseServerSideScanning: CloudUseServerSideScanningFlag.Clone(),
	}
}

func (f *CloudFlagGroup) Name() string {
	return "Trivy Cloud"
}

func (f *CloudFlagGroup) Flags() []Flagger {
	return []Flagger{
		f.CloudToken,
		f.CloudApiURL,
		f.CloudTrivyServerURL,
		f.CloudUploadResults,
		f.CloudSecretConfig,
		f.CloudMisconfigConfig,
		f.CloudUseServerSideScanning,
	}
}

// CloudLoginCredentials is the credentials used to authenticate with Trivy Cloud platform
// In the future this would likely have more information stored for refresh tokens, etc
type CloudLoginCredentials struct {
	Token string
}

type CloudOptions struct {
	CloudToken            string
	ApiURL                string
	TrivyServerURL        string
	UploadResults         bool
	SecretConfig          bool
	MisconfigConfig       bool
	UseServerSideScanning bool
}

// ToOptions converts the flags to options
func (f *CloudFlagGroup) ToOptions(opts *Options) error {
	opts.CloudOptions = CloudOptions{
		CloudToken:            f.CloudToken.Value(),
		ApiURL:                f.CloudApiURL.Value(),
		TrivyServerURL:        f.CloudTrivyServerURL.Value(),
		UploadResults:         f.CloudUploadResults.Value(),
		SecretConfig:          f.CloudSecretConfig.Value(),
		MisconfigConfig:       f.CloudMisconfigConfig.Value(),
		UseServerSideScanning: f.CloudUseServerSideScanning.Value(),
	}
	return nil
}
