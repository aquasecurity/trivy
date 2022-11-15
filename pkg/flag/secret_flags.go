package flag

var (
	SecretConfigFlag = Flag{
		Name:       "secret-config",
		ConfigName: "secret.config",
		Value:      "trivy-secret.yaml",
		Usage:      "specify a path to config file for secret scanning",
	}
	SecretOutputUncensoredFlag = Flag{
		Name:       "secret-output-uncensored",
		ConfigName: "secret.output-uncensored",
		Value:      "false",
		Usage:      "specify whether to censor the secret output",
	}
)

type SecretFlagGroup struct {
	SecretConfig     *Flag
	OutputUncensored *Flag
}

type SecretOptions struct {
	SecretConfigPath string
	OutputUncensored bool
}

func NewSecretFlagGroup() *SecretFlagGroup {
	return &SecretFlagGroup{
		SecretConfig:     &SecretConfigFlag,
		OutputUncensored: &SecretOutputUncensoredFlag,
	}
}

func (f *SecretFlagGroup) Name() string {
	return "Secret"
}

func (f *SecretFlagGroup) Flags() []*Flag {
	return []*Flag{f.SecretConfig, f.OutputUncensored}
}

func (f *SecretFlagGroup) ToOptions() SecretOptions {
	return SecretOptions{
		SecretConfigPath: getString(f.SecretConfig),
		OutputUncensored: getBool(f.OutputUncensored),
	}
}
