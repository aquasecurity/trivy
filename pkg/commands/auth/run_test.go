package auth_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/require"

	testauth "github.com/aquasecurity/testdocker/auth"
	"github.com/aquasecurity/testdocker/registry"
	"github.com/aquasecurity/trivy/pkg/commands/auth"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/flag"
)

func TestLogin(t *testing.T) {
	type args struct {
		registry string
		opts     flag.Options
	}
	tests := []struct {
		name    string
		args    args
		wantErr string
	}{
		{
			name: "single credential",
			args: args{
				opts: flag.Options{
					RegistryOptions: flag.RegistryOptions{
						Credentials: []types.Credential{
							{
								Username: "user",
								Password: "pass",
							},
						},
					},
				},
			},
		},
		{
			name: "multiple credentials",
			args: args{
				opts: flag.Options{
					RegistryOptions: flag.RegistryOptions{
						Credentials: []types.Credential{
							{
								Username: "user1",
								Password: "pass1",
							},
							{
								Username: "user2",
								Password: "pass2",
							},
						},
					},
				},
			},
			wantErr: "multiple credentials are not allowed",
		},
		{
			name: "no credentials",
			args: args{
				registry: "auth.test",
				opts:     flag.Options{},
			},
			wantErr: "username and password required",
		},
		{
			name: "invalid registry",
			args: args{
				registry: "aaa://invalid.test",
				opts: flag.Options{
					RegistryOptions: flag.RegistryOptions{
						Credentials: []types.Credential{
							{
								Username: "user",
								Password: "pass",
							},
						},
					},
				},
			},
			wantErr: "registries must be valid RFC 3986 URI authorities",
		},
	}

	tr := registry.NewDockerRegistry(registry.Option{
		Auth: testauth.Auth{
			User:     "user",
			Password: "pass",
		},
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set the DOCKER_CONFIG environment variable to a temporary directory
			// so that the test does not interfere with the user's configuration.
			t.Setenv("DOCKER_CONFIG", filepath.Join(t.TempDir(), "config.json"))

			reg := lo.Ternary(tt.args.registry == "", strings.TrimPrefix(tr.URL, "http://"), tt.args.registry)
			err := auth.Login(context.Background(), reg, tt.args.opts)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestLogout(t *testing.T) {
	// Set the DOCKER_CONFIG environment variable to a temporary directory
	// so that the test does not interfere with the user's configuration.
	tmpDir := t.TempDir()
	t.Setenv("DOCKER_CONFIG", tmpDir)

	t.Run("success", func(t *testing.T) {
		configFile := filepath.Join(tmpDir, "config.json")
		err := os.WriteFile(configFile, []byte(`{"auths": {"auth.test": {"auth": "dXNlcjpwYXNz"}}}`), 0600)
		require.NoError(t, err)

		err = auth.Logout(context.Background(), "auth.test")
		require.NoError(t, err)
		b, err := os.ReadFile(configFile)
		require.NoError(t, err)
		require.JSONEq(t, `{"auths": {}}`, string(b))
	})
	t.Run("not found", func(t *testing.T) {
		err := auth.Logout(context.Background(), "notfound.test")
		require.NoError(t, err) // Return an error if "credsStore" is "osxkeychain".
	})

	t.Run("invalid registry", func(t *testing.T) {
		err := auth.Logout(context.Background(), "aaa://invalid.test")
		require.ErrorContains(t, err, "registries must be valid RFC 3986 URI authorities")
	})
}
