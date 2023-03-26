package flag

import (
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

var (
	UsernameFlag = Flag{
		Name:       "username",
		ConfigName: "registry.username",
		Value:      []string{},
		Usage:      "username. Comma-separated usernames allowed.",
	}
	PasswordFlag = Flag{
		Name:       "password",
		ConfigName: "registry.password",
		Value:      []string{},
		Usage:      "password. Comma-separated passwords allowed. TRIVY_PASSWORD should be used for security reasons.",
	}
	RegistryTokenFlag = Flag{
		Name:       "registry-token",
		ConfigName: "registry.token",
		Value:      "",
		Usage:      "registry token",
	}
)

type RegistryFlagGroup struct {
	Username      *Flag
	Password      *Flag
	RegistryToken *Flag
}

type RegistryOptions struct {
	Credentials   []types.Credential
	RegistryToken string
}

func NewRegistryFlagGroup() *RegistryFlagGroup {
	return &RegistryFlagGroup{
		Username:      &UsernameFlag,
		Password:      &PasswordFlag,
		RegistryToken: &RegistryTokenFlag,
	}
}

func (f *RegistryFlagGroup) Name() string {
	return "Registry"
}

func (f *RegistryFlagGroup) Flags() []*Flag {
	return []*Flag{
		f.Username,
		f.Password,
		f.RegistryToken,
	}
}

func (f *RegistryFlagGroup) ToOptions() (RegistryOptions, error) {
	var credentials []types.Credential
	users := getStringSlice(f.Username)
	passwords := getStringSlice(f.Password)
	if len(users) != len(passwords) {
		return RegistryOptions{}, xerrors.New("the length of usernames and passwords must match")
	}
	for i, user := range users {
		credentials = append(credentials, types.Credential{
			Username: strings.TrimSpace(user),
			Password: strings.TrimSpace(passwords[i]),
		})
	}

	return RegistryOptions{
		Credentials:   credentials,
		RegistryToken: getString(f.RegistryToken),
	}, nil
}
