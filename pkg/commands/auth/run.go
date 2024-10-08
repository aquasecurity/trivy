package auth

import (
	"context"
	"net/http"
	"os"

	"github.com/docker/cli/cli/config"
	"github.com/docker/cli/cli/config/types"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
)

func Login(ctx context.Context, registry string, opts flag.Options) error {
	if len(opts.Credentials) == 0 {
		return xerrors.New("username and password required")
	} else if len(opts.Credentials) > 1 {
		return xerrors.New("multiple credentials are not allowed")
	}

	reg, err := parseRegistry(registry, opts)
	if err != nil {
		return xerrors.Errorf("failed to parse registry: %w", err)
	}
	serverAddress := reg.Name()

	// Validate the credential
	_, err = transport.NewWithContext(ctx, reg, &authn.Basic{
		Username: opts.Credentials[0].Username,
		Password: opts.Credentials[0].Password,
	}, httpTransport(opts), []string{reg.Scope(transport.PullScope)})
	if err != nil {
		return xerrors.Errorf("failed to authenticate: %w", err)
	}

	cf, err := config.Load(os.Getenv("DOCKER_CONFIG"))
	if err != nil {
		return xerrors.Errorf("failed to load docker config: %w", err)
	}
	creds := cf.GetCredentialsStore(serverAddress)
	if serverAddress == name.DefaultRegistry {
		serverAddress = authn.DefaultAuthKey
	}
	if err := creds.Store(types.AuthConfig{
		ServerAddress: serverAddress,
		Username:      opts.Credentials[0].Username,
		Password:      opts.Credentials[0].Password,
	}); err != nil {
		return xerrors.Errorf("failed to store credentials: %w", err)
	}

	if err := cf.Save(); err != nil {
		return xerrors.Errorf("failed to save docker config: %w", err)
	}
	log.Info("Login succeeded", log.FilePath(cf.Filename), log.String("username", opts.Credentials[0].Username))
	return nil
}

func Logout(_ context.Context, registry string) error {
	reg, err := parseRegistry(registry, flag.Options{})
	if err != nil {
		return xerrors.Errorf("failed to parse registry: %w", err)
	}
	serverAddress := reg.Name()

	cf, err := config.Load(os.Getenv("DOCKER_CONFIG"))
	if err != nil {
		return xerrors.Errorf("failed to load docker config: %w", err)
	}
	creds := cf.GetCredentialsStore(serverAddress)
	if serverAddress == name.DefaultRegistry {
		serverAddress = authn.DefaultAuthKey
	}
	if err := creds.Erase(serverAddress); err != nil {
		return xerrors.Errorf("failed to delete credentials: %w", err)
	}

	if err := cf.Save(); err != nil {
		return xerrors.Errorf("failed to save docker config: %w", err)
	}
	log.Info("Logged out", log.FilePath(cf.Filename))
	return nil
}

func parseRegistry(registry string, opts flag.Options) (name.Registry, error) {
	var nameOpts []name.Option
	if opts.Insecure {
		nameOpts = append(nameOpts, name.Insecure)
	}
	reg, err := name.NewRegistry(registry, nameOpts...)
	if err != nil {
		return name.Registry{}, xerrors.Errorf("failed to parse registry: %w", err)
	}
	return reg, nil
}

func httpTransport(opts flag.Options) *http.Transport {
	tr := remote.DefaultTransport.(*http.Transport).Clone()
	if opts.Insecure {
		tr.TLSClientConfig.InsecureSkipVerify = true
	}
	return tr
}
