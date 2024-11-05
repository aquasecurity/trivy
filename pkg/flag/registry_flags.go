package flag

import (
	"io"
	"os"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

var (
	UsernameFlag = Flag[[]string]{
		Name:       "username",
		ConfigName: "registry.username",
		Usage:      "username. Comma-separated usernames allowed.",
	}
	PasswordFlag = Flag[[]string]{
		Name:       "password",
		ConfigName: "registry.password",
		Usage:      "password. Comma-separated passwords allowed. TRIVY_PASSWORD should be used for security reasons.",
	}
	PasswordStdinFlag = Flag[bool]{
		Name:       "password-stdin",
		ConfigName: "registry.password-stdin",
		Usage:      "password from stdin. Comma-separated passwords are not supported.",
	}
	RegistryTokenFlag = Flag[string]{
		Name:       "registry-token",
		ConfigName: "registry.token",
		Usage:      "registry token",
	}
)

type RegistryFlagGroup struct {
	Username      *Flag[[]string]
	Password      *Flag[[]string]
	PasswordStdin *Flag[bool]
	RegistryToken *Flag[string]
}

type RegistryOptions struct {
	Credentials   []types.Credential
	RegistryToken string
}

func NewRegistryFlagGroup() *RegistryFlagGroup {
	return &RegistryFlagGroup{
		Username:      UsernameFlag.Clone(),
		Password:      PasswordFlag.Clone(),
		PasswordStdin: PasswordStdinFlag.Clone(),
		RegistryToken: RegistryTokenFlag.Clone(),
	}
}

func (f *RegistryFlagGroup) Name() string {
	return "Registry"
}

func (f *RegistryFlagGroup) Flags() []Flagger {
	return []Flagger{
		f.Username,
		f.Password,
		f.PasswordStdin,
		f.RegistryToken,
	}
}

func (f *RegistryFlagGroup) ToOptions() (RegistryOptions, error) {
	if err := parseFlags(f); err != nil {
		return RegistryOptions{}, err
	}

	var credentials []types.Credential
	users := f.Username.Value()
	passwords := f.Password.Value()
	if f.PasswordStdin.Value() {
		if len(passwords) != 0 {
			return RegistryOptions{}, xerrors.New("'--password' and '--password-stdin' can't be used at the same time")
		}
		contents, err := io.ReadAll(os.Stdin)
		if err != nil {
			return RegistryOptions{}, xerrors.Errorf("failed to read from stdin: %w", err)
		}
		// "--password-stdin" doesn't support comma-separated passwords
		passwords = []string{strings.TrimRight(string(contents), "\r\n")}
	}
	if len(users) != len(passwords) {
		return RegistryOptions{}, xerrors.New("the number of usernames and passwords must match")
	}
	for i, user := range users {
		credentials = append(credentials, types.Credential{
			Username: strings.TrimSpace(user),
			Password: strings.TrimSpace(passwords[i]),
		})
	}

	return RegistryOptions{
		Credentials:   credentials,
		RegistryToken: f.RegistryToken.Value(),
	}, nil
}
