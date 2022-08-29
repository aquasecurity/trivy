package flag

var (
	SecretConfigFlag = Flag{
		Name:       "secret-config",
		ConfigName: "secret.config",
		Value:      "trivy-secret.yaml",
		Usage:      "specify a path to config file for secret scanning",
	}
)

type SecretFlagGroup struct {
	SecretConfig *Flag
}

type SecretOptions struct {
	SecretConfigPath string
}

func NewSecretFlagGroup() *SecretFlagGroup {
	return &SecretFlagGroup{
		SecretConfig: &SecretConfigFlag,
	}
}

func (f *SecretFlagGroup) Name() string {
	return "Secret"
}

func (f *SecretFlagGroup) Flags() []*Flag {
	return []*Flag{f.SecretConfig}
}

func (f *SecretFlagGroup) ToOptions() SecretOptions {
	return SecretOptions{
		SecretConfigPath: getString(f.SecretConfig),
	}
}
