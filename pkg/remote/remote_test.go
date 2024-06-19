package remote

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/testdocker/auth"
	"github.com/aquasecurity/testdocker/registry"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/version/app"
)

func setupPrivateRegistry() *httptest.Server {
	imagePaths := map[string]string{
		"v2/library/alpine:3.10": "../fanal/test/testdata/alpine-310.tar.gz",
	}
	tr := registry.NewDockerRegistry(registry.Option{
		Images: imagePaths,
		Auth: auth.Auth{
			User:     "test",
			Password: "testpass",
			Secret:   "secret",
		},
	})

	tr.Config.Handler = newUserAgentsTrackingHandler(tr.Config.Handler)
	return tr
}

// setupConfigDir sets up an isolated configDir() for this test.
func setupConfigDir(t *testing.T) string {
	p := t.TempDir()
	t.Setenv("DOCKER_CONFIG", p)
	return p
}

func setupDockerConfig(t *testing.T, content string) {
	cd := setupConfigDir(t)
	p := filepath.Join(cd, "config.json")

	err := os.WriteFile(p, []byte(content), 0600)
	require.NoError(t, err)
}

func encode(user, pass string) string {
	delimited := fmt.Sprintf("%s:%s", user, pass)
	return base64.StdEncoding.EncodeToString([]byte(delimited))
}

func TestGet(t *testing.T) {
	tr := setupPrivateRegistry()
	defer tr.Close()

	serverAddr := tr.Listener.Addr().String()

	type args struct {
		imageName string
		config    string
		option    types.RegistryOptions
	}
	tests := []struct {
		name    string
		args    args
		want    *Descriptor
		wantErr string
	}{
		{
			name: "single credential",
			args: args{
				imageName: fmt.Sprintf("%s/library/alpine:3.10", serverAddr),
				option: types.RegistryOptions{
					Credentials: []types.Credential{
						{
							Username: "test",
							Password: "testpass",
						},
					},
					Insecure: true,
				},
			},
		},
		{
			name: "multiple credential",
			args: args{
				imageName: fmt.Sprintf("%s/library/alpine:3.10", serverAddr),
				option: types.RegistryOptions{
					Credentials: []types.Credential{
						{
							Username: "foo",
							Password: "bar",
						},
						{
							Username: "test",
							Password: "testpass",
						},
					},
					Insecure: true,
				},
			},
		},
		{
			name: "keychain",
			args: args{
				imageName: fmt.Sprintf("%s/library/alpine:3.10", serverAddr),
				config:    fmt.Sprintf(`{"auths": {%q: {"auth": %q}}}`, serverAddr, encode("test", "testpass")),
				option: types.RegistryOptions{
					Insecure: true,
				},
			},
		},
		{
			name: "platform",
			args: args{
				imageName: fmt.Sprintf("%s/library/alpine:3.10", serverAddr),
				option: types.RegistryOptions{
					Credentials: []types.Credential{
						{
							Username: "test",
							Password: "testpass",
						},
					},
					Insecure: true,
					Platform: types.Platform{
						Platform: &v1.Platform{
							OS:           "",
							Architecture: "amd64",
						},
					},
				},
			},
		},
		{
			name: "force platform",
			args: args{
				imageName: fmt.Sprintf("%s/library/alpine:3.10", serverAddr),
				option: types.RegistryOptions{
					Credentials: []types.Credential{
						{
							Username: "test",
							Password: "testpass",
						},
					},
					Insecure: true,
					Platform: types.Platform{
						Force: true,
						Platform: &v1.Platform{
							OS:           "windows",
							Architecture: "amd64",
						},
					},
				},
			},
			wantErr: "the specified platform not found",
		},
		{
			name: "bad credential",
			args: args{
				imageName: fmt.Sprintf("%s/library/alpine:3.10", serverAddr),
				option: types.RegistryOptions{
					Credentials: []types.Credential{
						{
							Username: "foo",
							Password: "bar",
						},
					},
					Insecure: true,
				},
			},
			wantErr: "invalid username/password",
		},
		{
			name: "bad keychain",
			args: args{
				imageName: fmt.Sprintf("%s/library/alpine:3.10", serverAddr),
				config:    fmt.Sprintf(`{"auths": {%q: {"auth": %q}}}`, serverAddr, encode("foo", "bar")),
				option: types.RegistryOptions{
					Insecure: true,
				},
			},
			wantErr: "invalid username/password",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, err := name.ParseReference(tt.args.imageName)
			require.NoError(t, err)

			if tt.args.config != "" {
				setupDockerConfig(t, tt.args.config)
			}

			_, err = Get(context.Background(), n, tt.args.option)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

type userAgentsTrackingHandler struct {
	hr http.Handler

	mu     sync.Mutex
	agents map[string]struct{}
}

func newUserAgentsTrackingHandler(hr http.Handler) *userAgentsTrackingHandler {
	return &userAgentsTrackingHandler{hr: hr, agents: make(map[string]struct{})}
}

func (uh *userAgentsTrackingHandler) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	for _, agent := range r.Header["User-Agent"] {
		// Skip test framework user agent
		if agent != "Go-http-client/1.1" {
			uh.agents[agent] = struct{}{}
		}
	}
	uh.hr.ServeHTTP(rw, r)
}

func setupAgentTrackingRegistry() (*httptest.Server, *userAgentsTrackingHandler) {
	imagePaths := map[string]string{
		"v2/library/alpine:3.10": "../fanal/test/testdata/alpine-310.tar.gz",
	}
	tr := registry.NewDockerRegistry(registry.Option{
		Images: imagePaths,
	})

	tracker := newUserAgentsTrackingHandler(tr.Config.Handler)
	tr.Config.Handler = tracker

	return tr, tracker
}

func TestUserAgents(t *testing.T) {
	tr, tracker := setupAgentTrackingRegistry()
	defer tr.Close()

	serverAddr := tr.Listener.Addr().String()

	n, err := name.ParseReference(fmt.Sprintf("%s/library/alpine:3.10", serverAddr))
	require.NoError(t, err)

	_, err = Get(context.Background(), n, types.RegistryOptions{
		Credentials: []types.Credential{
			{
				Username: "test",
				Password: "testpass",
			},
		},
		Insecure: true,
	})
	require.NoError(t, err)

	require.Len(t, tracker.agents, 1)
	_, ok := tracker.agents[fmt.Sprintf("trivy/%s go-containerregistry", app.Version())]
	require.True(t, ok, `user-agent header equals to "trivy/dev go-containerregistry"`)
}
