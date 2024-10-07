package auth_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

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
				registry: "auth.test",
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
				registry: "auth.test",
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
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set the DOCKER_CONFIG environment variable to a temporary directory
			// so that the test does not interfere with the user's configuration.
			t.Setenv("DOCKER_CONFIG", filepath.Join(t.TempDir(), "config.json"))

			err := auth.Login(context.Background(), tt.args.registry, tt.args.opts)
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
	t.Setenv("DOCKER_CONFIG", t.TempDir())

	t.Run("success", func(t *testing.T) {
		err := auth.Login(context.Background(), "auth.test", flag.Options{
			RegistryOptions: flag.RegistryOptions{
				Credentials: []types.Credential{
					{
						Username: "user",
						Password: "pass",
					},
				},
			},
		})
		require.NoError(t, err)
		err = auth.Logout(context.Background(), "auth.test")
		require.NoError(t, err)
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
