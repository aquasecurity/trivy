package image

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/aquasecurity/fanal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewImage(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.String(), "unknown"):
			w.WriteHeader(404)
			return
		case strings.Contains(r.URL.String(), "invalid_json"):
			w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
			w.Write([]byte(`{invalid}`))
		default:
			b, _ := ioutil.ReadFile("testdata/manifest.json")
			w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
			w.Write(b)
		}
	}))
	defer ts.Close()

	tsurl := strings.TrimPrefix(ts.URL, "http://")

	type args struct {
		image      Reference
		transports []string
		option     types.DockerOption
	}
	type image struct {
		name       string
		isFile     bool
		transports []string
	}
	tests := []struct {
		name      string
		args      args
		wantImage image
		wantErr   string
	}{
		{
			name: "happy path",
			args: args{
				image: Reference{
					Name:   fmt.Sprintf("%s/foobar", tsurl),
					IsFile: false,
				},
				transports: []string{"docker://"},
				option: types.DockerOption{
					SkipPing:              true,
					InsecureSkipTLSVerify: true,
				},
			},
			wantImage: image{
				name:       fmt.Sprintf("%s/foobar", tsurl),
				isFile:     false,
				transports: []string{"docker://"},
			},
		},
		{
			name: "happy path without latest tag",
			args: args{
				image: Reference{
					Name:   fmt.Sprintf("%s/foobar", tsurl),
					IsFile: false,
				},
				transports: []string{"docker://"},
				option: types.DockerOption{
					InsecureSkipTLSVerify: true,
				},
			},
			wantImage: image{
				name:       fmt.Sprintf("%s/foobar", tsurl),
				isFile:     false,
				transports: []string{"docker://"},
			},
		},
		{
			name: "happy path with a tar file",
			args: args{
				image: Reference{
					Name:   "testdata/alpine-310.tar.gz",
					IsFile: true,
				},
				transports: []string{"docker-archive:"},
			},
			wantImage: image{
				name:       "testdata/alpine-310.tar.gz",
				isFile:     true,
				transports: []string{"docker-archive:"},
			},
		},
		{
			name: "sad path: invalid image name",
			args: args{
				image: Reference{
					Name:   "ALPINE",
					IsFile: false,
				},
				transports: []string{"docker-archive:"},
			},
			wantErr: "invalid image name",
		},
		{
			name: "sad path: invalid image name",
			args: args{
				image: Reference{
					Name:   "alpine:3.10",
					IsFile: false,
				},
				transports: []string{"invalid:"},
			},
			wantErr: `unknown transport "invalid"`,
		},
		{
			name: "sad path: non-existed image name",
			args: args{
				image: Reference{
					Name:   fmt.Sprintf("%s/unknown:3.10", tsurl),
					IsFile: false,
				},
				transports: []string{"docker://"},
				option: types.DockerOption{
					SkipPing:              true,
					InsecureSkipTLSVerify: true,
				},
			},
			wantErr: `unexpected end of JSON input`,
		},
		{
			name: "sad path: invalid manifest JSON",
			args: args{
				image: Reference{
					Name:   fmt.Sprintf("%s/invalid_json:3.10", tsurl),
					IsFile: false,
				},
				transports: []string{"docker://"},
				option: types.DockerOption{
					SkipPing:              true,
					InsecureSkipTLSVerify: true,
				},
			},
			wantErr: `failed to initialize: invalid character`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			got, err := NewImage(ctx, tt.args.image, tt.args.transports, tt.args.option)
			if tt.wantErr != "" {
				require.NotNil(t, err, tt.name)
				require.Contains(t, err.Error(), tt.wantErr, tt.name)
				return
			} else {
				require.NoError(t, err, tt.name)
			}

			assert.Equal(t, tt.wantImage.name, got.name, tt.name)
		})
	}
}

func TestRealImage_LayerIDs(t *testing.T) {
	tests := []struct {
		name      string
		imageFile string
		want      []string
	}{
		{
			name:      "happy path",
			imageFile: "testdata/alpine-310.tar.gz",
			want:      []string{"sha256:531743b7098cb2aaf615641007a129173f63ed86ca32fe7b5a246a1c47286028"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			img, err := NewImage(context.Background(), Reference{
				Name:   tt.imageFile,
				IsFile: true,
			}, []string{"docker-archive:"}, types.DockerOption{})
			require.NoError(t, err, tt.name)

			if got := img.LayerIDs(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LayerIDs() = %v, want %v", got, tt.want)
			}
		})
	}
}
