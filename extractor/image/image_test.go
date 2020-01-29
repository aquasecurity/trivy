package image

import (
	"bytes"
	"context"
	"io/ioutil"
	"testing"

	"github.com/opencontainers/go-digest"

	imageTypes "github.com/containers/image/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/types"
)

func TestNewImage(t *testing.T) {
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
		name              string
		args              args
		wantImage         image
		wantSystemContext *imageTypes.SystemContext
		wantErr           string
	}{
		{
			name: "happy path",
			args: args{
				image: Reference{
					Name:   "alpine:3.10",
					IsFile: false,
				},
				transports: []string{"docker-daemon:"},
				option: types.DockerOption{
					SkipPing:              true,
					InsecureSkipTLSVerify: true,
				},
			},
			wantImage: image{
				name:       "docker.io/library/alpine:3.10",
				isFile:     false,
				transports: []string{"docker-daemon:"},
			},
			wantSystemContext: &imageTypes.SystemContext{
				OSChoice:                          "linux",
				OCIInsecureSkipTLSVerify:          true,
				DockerInsecureSkipTLSVerify:       imageTypes.NewOptionalBool(true),
				DockerDisableV1Ping:               true,
				DockerDaemonInsecureSkipTLSVerify: true,
			},
		},
		{
			name: "happy path without latest tag",
			args: args{
				image: Reference{
					Name:   "alpine",
					IsFile: false,
				},
				transports: []string{"docker-daemon:"},
			},
			wantImage: image{
				name:       "docker.io/library/alpine:latest",
				isFile:     false,
				transports: []string{"docker-daemon:"},
			},
			wantSystemContext: &imageTypes.SystemContext{
				OSChoice:                    "linux",
				DockerInsecureSkipTLSVerify: imageTypes.NewOptionalBool(false),
			},
		},
		{
			name: "happy path with quay.io",
			args: args{
				image: Reference{
					Name:   "quay.io/prometheus/node-exporter:v0.18.1",
					IsFile: false,
				},
				transports: []string{"docker-daemon:", "docker://"},
			},
			wantImage: image{
				name:       "quay.io/prometheus/node-exporter:v0.18.1",
				isFile:     false,
				transports: []string{"docker-daemon:", "docker://"},
			},
			wantSystemContext: &imageTypes.SystemContext{
				OSChoice:                    "linux",
				DockerInsecureSkipTLSVerify: imageTypes.NewOptionalBool(false),
			},
		},
		{
			name: "happy path with a tar file",
			args: args{
				image: Reference{
					Name:   "/tmp/alpine-3.10.tar",
					IsFile: true,
				},
				transports: []string{"docker-archive:"},
			},
			wantImage: image{
				name:       "/tmp/alpine-3.10.tar",
				isFile:     true,
				transports: []string{"docker-archive:"},
			},
			wantSystemContext: &imageTypes.SystemContext{
				OSChoice:                    "linux",
				DockerInsecureSkipTLSVerify: imageTypes.NewOptionalBool(false),
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
			wantImage: image{
				name:       "/tmp/alpine-3.10.tar",
				isFile:     true,
				transports: []string{"docker-archive:"},
			},
			wantSystemContext: &imageTypes.SystemContext{
				OSChoice:                    "linux",
				DockerInsecureSkipTLSVerify: imageTypes.NewOptionalBool(false),
			},
			wantErr: "invalid image name",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			got, err := NewImage(ctx, tt.args.image, tt.args.transports, tt.args.option, nil)
			if tt.wantErr != "" {
				require.NotNil(t, err, tt.name)
				require.Contains(t, err.Error(), tt.wantErr, tt.name)
				return
			} else {
				require.NoError(t, err, tt.name)
			}

			assert.Equal(t, tt.wantSystemContext, got.systemContext, tt.name)
			assert.Equal(t, tt.wantImage.name, got.name, tt.name)
			assert.Equal(t, tt.wantImage.isFile, got.isFile, tt.name)
			assert.Equal(t, tt.wantImage.transports, got.transports, tt.name)
		})
	}
}

func TestImage_LayerInfos(t *testing.T) {
	type fields struct {
		name       string
		isFile     bool
		transports []string
	}
	tests := []struct {
		name          string
		fields        fields
		cacheGet      []cache.GetExpectation
		cacheSetBytes []cache.SetBytesExpectation
		want          []imageTypes.BlobInfo
		wantErr       string
	}{
		{
			name: "happy path without cache",
			fields: fields{
				name:       "testdata/alpine-310.tar.gz",
				isFile:     true,
				transports: []string{"docker-archive:"},
			},
			want: []imageTypes.BlobInfo{
				{
					Size:      5818880,
					Digest:    "sha256:531743b7098cb2aaf615641007a129173f63ed86ca32fe7b5a246a1c47286028",
					MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip",
				},
			},
		},
		{
			name: "happy path with cache",
			fields: fields{
				name:   "docker.io/library/alpine:3.11",
				isFile: false,
			},
			cacheGet: []cache.GetExpectation{
				{
					Args: cache.GetArgs{
						Key: "layerinfos::docker.io/library/alpine:3.11",
					},
					Returns: cache.GetReturns{Reader: ioutil.NopCloser(
						bytes.NewBuffer([]byte(`[{"Digest":"sha256:e6b0cf9c0882fb079c9d35361d12ff4691f916b6d825061247d1bd0b26d7cf3f","Size":2801778,"MediaType":"application/vnd.docker.image.rootfs.diff.tar.gzip"}]`)),
					),
					},
				},
			},
			want: []imageTypes.BlobInfo{
				{
					Size:      2801778,
					Digest:    "sha256:e6b0cf9c0882fb079c9d35361d12ff4691f916b6d825061247d1bd0b26d7cf3f",
					MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip",
				},
			},
		},
		{
			name: "happy path: cache.Get returns an error, but it is ignored",
			fields: fields{
				name:       "testdata/alpine-310.tar.gz",
				isFile:     false, // This never happens. For testing.
				transports: []string{"docker-archive:"},
			},
			cacheGet: []cache.GetExpectation{
				{
					Args: cache.GetArgs{
						Key: "layerinfos::testdata/alpine-310.tar.gz",
					},
					Returns: cache.GetReturns{Reader: ioutil.NopCloser(
						bytes.NewBuffer([]byte(`[{"invalid"}]`)),
					),
					},
				},
			},
			cacheSetBytes: []cache.SetBytesExpectation{
				{
					Args: cache.SetBytesArgs{
						Key:           "layerinfos::testdata/alpine-310.tar.gz",
						ValueAnything: true,
					},
					Returns: cache.SetBytesReturns{Err: nil},
				},
			},
			want: []imageTypes.BlobInfo{
				{
					Size:      5818880,
					Digest:    "sha256:531743b7098cb2aaf615641007a129173f63ed86ca32fe7b5a246a1c47286028",
					MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip",
				},
			},
		},
		{
			name: "happy path: cache.SetBytes returns an error, but it is ignored",
			fields: fields{
				name:       "testdata/alpine-310.tar.gz",
				isFile:     false, // This never happens. For testing.
				transports: []string{"docker-archive:"},
			},
			cacheGet: []cache.GetExpectation{
				{
					Args: cache.GetArgs{
						Key: "layerinfos::testdata/alpine-310.tar.gz",
					},
					Returns: cache.GetReturns{Reader: nil},
				},
			},
			cacheSetBytes: []cache.SetBytesExpectation{
				{
					Args: cache.SetBytesArgs{
						Key:           "layerinfos::testdata/alpine-310.tar.gz",
						ValueAnything: true,
					},
					Returns: cache.SetBytesReturns{Err: xerrors.New("error")},
				},
			},
			want: []imageTypes.BlobInfo{
				{
					Size:      5818880,
					Digest:    "sha256:531743b7098cb2aaf615641007a129173f63ed86ca32fe7b5a246a1c47286028",
					MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip",
				},
			},
		},
		{
			name: "sad path: no such tar file",
			fields: fields{
				name:       "testdata/unknown.tar",
				isFile:     true,
				transports: []string{"docker-archive:"},
			},
			want: []imageTypes.BlobInfo{
				{
					Size:   100,
					Digest: "sha256:e6b0cf9c0882fb079c9d35361d12ff4691f916b6d825061247d1bd0b26d7cf3f",
				},
			},
			wantErr: "no such file or directory",
		},
		{
			name: "sad path: no transport",
			fields: fields{
				name:   "testdata/unknown.tar",
				isFile: true,
			},
			want: []imageTypes.BlobInfo{
				{
					Size:   100,
					Digest: "sha256:e6b0cf9c0882fb079c9d35361d12ff4691f916b6d825061247d1bd0b26d7cf3f",
				},
			},
			wantErr: "no valid transport",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := new(cache.MockCache)
			c.ApplyGetExpectations(tt.cacheGet)
			c.ApplySetBytesExpectations(tt.cacheSetBytes)

			img := &Image{
				name:       tt.fields.name,
				isFile:     tt.fields.isFile,
				transports: tt.fields.transports,
				cache:      c,
			}
			got, err := img.LayerInfos()
			if tt.wantErr != "" {
				require.NotNil(t, err, tt.name)
				require.Contains(t, err.Error(), tt.wantErr, tt.name)
				return
			} else {
				require.NoError(t, err, tt.name)
			}

			assert.Equal(t, tt.want, got, tt.name)

			c.AssertExpectations(t)
		})
	}
}

func TestImage_ConfigBlob(t *testing.T) {
	type fields struct {
		name       string
		isFile     bool
		transports []string
	}
	tests := []struct {
		name          string
		fields        fields
		cacheGet      []cache.GetExpectation
		cacheSetBytes []cache.SetBytesExpectation
		//configBlob    []ConfigBlobExpectation
		want    string
		wantErr string
	}{
		{
			name: "happy path without cache",
			fields: fields{
				name:       "testdata/alpine-310.tar.gz",
				isFile:     true,
				transports: []string{"docker-archive:"},
			},
			want: `{"architecture":"amd64","config":{"Hostname":"","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/bin/sh"],"ArgsEscaped":true,"Image":"sha256:7c41e139ba64dd2eba852a2e963ee86f2e8da3a5bbfaf10cf4349535dbf0ff08","Volumes":null,"WorkingDir":"","Entrypoint":null,"OnBuild":null,"Labels":null},"container":"7f4a36a667d138b079b5ff059485ff65bfbb5ebc48f24a89f983b918e73f4f28","container_config":{"Hostname":"7f4a36a667d1","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/bin/sh","-c","#(nop) ","CMD [\"/bin/sh\"]"],"ArgsEscaped":true,"Image":"sha256:7c41e139ba64dd2eba852a2e963ee86f2e8da3a5bbfaf10cf4349535dbf0ff08","Volumes":null,"WorkingDir":"","Entrypoint":null,"OnBuild":null,"Labels":{}},"created":"2020-01-23T16:53:06.686519038Z","docker_version":"18.06.1-ce","history":[{"created":"2020-01-23T16:53:06.551172402Z","created_by":"/bin/sh -c #(nop) ADD file:d48cac34fac385cbc1de6adfdd88300f76f9bbe346cd17e64fd834d042a98326 in / "},{"created":"2020-01-23T16:53:06.686519038Z","created_by":"/bin/sh -c #(nop)  CMD [\"/bin/sh\"]","empty_layer":true}],"os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:531743b7098cb2aaf615641007a129173f63ed86ca32fe7b5a246a1c47286028"]}}`,
		},
		{
			name: "happy path with cache",
			fields: fields{
				name:   "docker.io/library/alpine:3.11",
				isFile: false,
			},
			cacheGet: []cache.GetExpectation{
				{
					Args: cache.GetArgs{
						Key: "configblob::docker.io/library/alpine:3.11",
					},
					Returns: cache.GetReturns{Reader: ioutil.NopCloser(bytes.NewBuffer([]byte(`foo`)))},
				},
			},
			want: `foo`,
		},
		{
			name: "happy path: cache.SetBytes returns an error, but it is ignored",
			fields: fields{
				name:       "testdata/alpine-310.tar.gz",
				isFile:     false, // This never happens. For testing.
				transports: []string{"docker-archive:"},
			},
			cacheGet: []cache.GetExpectation{
				{
					Args: cache.GetArgs{
						Key: "configblob::testdata/alpine-310.tar.gz",
					},
					Returns: cache.GetReturns{Reader: nil},
				},
			},
			cacheSetBytes: []cache.SetBytesExpectation{
				{
					Args: cache.SetBytesArgs{
						Key:           "configblob::testdata/alpine-310.tar.gz",
						ValueAnything: true,
					},
					Returns: cache.SetBytesReturns{Err: xerrors.New("error")},
				},
			},
			want: `{"architecture":"amd64","config":{"Hostname":"","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/bin/sh"],"ArgsEscaped":true,"Image":"sha256:7c41e139ba64dd2eba852a2e963ee86f2e8da3a5bbfaf10cf4349535dbf0ff08","Volumes":null,"WorkingDir":"","Entrypoint":null,"OnBuild":null,"Labels":null},"container":"7f4a36a667d138b079b5ff059485ff65bfbb5ebc48f24a89f983b918e73f4f28","container_config":{"Hostname":"7f4a36a667d1","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/bin/sh","-c","#(nop) ","CMD [\"/bin/sh\"]"],"ArgsEscaped":true,"Image":"sha256:7c41e139ba64dd2eba852a2e963ee86f2e8da3a5bbfaf10cf4349535dbf0ff08","Volumes":null,"WorkingDir":"","Entrypoint":null,"OnBuild":null,"Labels":{}},"created":"2020-01-23T16:53:06.686519038Z","docker_version":"18.06.1-ce","history":[{"created":"2020-01-23T16:53:06.551172402Z","created_by":"/bin/sh -c #(nop) ADD file:d48cac34fac385cbc1de6adfdd88300f76f9bbe346cd17e64fd834d042a98326 in / "},{"created":"2020-01-23T16:53:06.686519038Z","created_by":"/bin/sh -c #(nop)  CMD [\"/bin/sh\"]","empty_layer":true}],"os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:531743b7098cb2aaf615641007a129173f63ed86ca32fe7b5a246a1c47286028"]}}`,
		},
		{
			name: "sad path: no such tar file",
			fields: fields{
				name:       "testdata/unknown.tar",
				isFile:     true,
				transports: []string{"docker-archive:"},
			},
			wantErr: "no such file or directory",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := new(cache.MockCache)
			c.ApplyGetExpectations(tt.cacheGet)
			c.ApplySetBytesExpectations(tt.cacheSetBytes)

			img := &Image{
				name:       tt.fields.name,
				isFile:     tt.fields.isFile,
				transports: tt.fields.transports,
				cache:      c,
			}
			got, err := img.ConfigBlob(context.Background())
			if tt.wantErr != "" {
				require.NotNil(t, err, tt.name)
				require.Contains(t, err.Error(), tt.wantErr, tt.name)
				return
			} else {
				require.NoError(t, err, tt.name)
			}

			assert.Equal(t, tt.want, string(got), tt.name)

			c.AssertExpectations(t)
		})
	}
}

func TestImage_GetBlob(t *testing.T) {
	type fields struct {
		name       string
		isFile     bool
		transports []string
	}
	tests := []struct {
		name     string
		fields   fields
		dig      digest.Digest
		cacheGet []cache.GetExpectation
		cacheSet []cache.SetExpectation
		want     []byte
		wantErr  string
	}{
		{
			name: "happy path without cache",
			fields: fields{
				name:       "testdata/alpine-310.tar.gz",
				isFile:     true,
				transports: []string{"docker-archive:"},
			},
			dig: "sha256:531743b7098cb2aaf615641007a129173f63ed86ca32fe7b5a246a1c47286028",
			cacheGet: []cache.GetExpectation{
				{
					Args: cache.GetArgs{
						Key: "sha256:531743b7098cb2aaf615641007a129173f63ed86ca32fe7b5a246a1c47286028",
					},
					Returns: cache.GetReturns{Reader: nil},
				},
			},
			cacheSet: []cache.SetExpectation{
				{
					Args: cache.SetArgs{
						Key:          "sha256:531743b7098cb2aaf615641007a129173f63ed86ca32fe7b5a246a1c47286028",
						FileAnything: true,
					},
					Returns: cache.SetReturns{
						Reader: ioutil.NopCloser(bytes.NewBuffer([]byte(`foo`))),
					},
				},
			},
			want: []byte(`foo`),
		},
		{
			name: "happy path with cache",
			fields: fields{
				name:       "testdata/alpine-310.tar.gz",
				isFile:     true,
				transports: []string{"docker-archive:"},
			},
			dig: "sha256:531743b7098cb2aaf615641007a129173f63ed86ca32fe7b5a246a1c47286028",
			cacheGet: []cache.GetExpectation{
				{
					Args: cache.GetArgs{
						Key: "sha256:531743b7098cb2aaf615641007a129173f63ed86ca32fe7b5a246a1c47286028",
					},
					Returns: cache.GetReturns{
						Reader: ioutil.NopCloser(bytes.NewBuffer([]byte(`foo`))),
					},
				},
			},
			want: []byte(`foo`),
		},
		{
			name: "sad path: no such tar file",
			fields: fields{
				name:       "testdata/unknown.tar",
				isFile:     true,
				transports: []string{"docker-archive:"},
			},
			dig: "sha256:531743b7098cb2aaf615641007a129173f63ed86ca32fe7b5a246a1c47286028",
			cacheGet: []cache.GetExpectation{
				{
					Args: cache.GetArgs{
						Key: "sha256:531743b7098cb2aaf615641007a129173f63ed86ca32fe7b5a246a1c47286028",
					},
					Returns: cache.GetReturns{Reader: nil},
				},
			},
			cacheSet: []cache.SetExpectation{
				{
					Args: cache.SetArgs{
						Key:          "sha256:e6b0cf9c0882fb079c9d35361d12ff4691f916b6d825061247d1bd0b26d7cf3f",
						FileAnything: true,
					},
					Returns: cache.SetReturns{
						Reader: ioutil.NopCloser(bytes.NewBuffer([]byte(`foo`))),
					},
				},
			},
			wantErr: "no such file or directory",
		},
		{
			name: "sad path without cache, GetBlob returns an error",
			fields: fields{
				name:       "testdata/alpine-310.tar.gz",
				isFile:     true,
				transports: []string{"docker-archive:"},
			},
			dig: "sha256:invalid",
			cacheGet: []cache.GetExpectation{
				{
					Args: cache.GetArgs{
						Key: "sha256:invalid",
					},
					Returns: cache.GetReturns{Reader: nil},
				},
			},
			cacheSet: []cache.SetExpectation{
				{
					Args: cache.SetArgs{
						Key:          "sha256:e6b0cf9c0882fb079c9d35361d12ff4691f916b6d825061247d1bd0b26d7cf3f",
						FileAnything: true,
					},
					Returns: cache.SetReturns{
						Reader: ioutil.NopCloser(bytes.NewBuffer([]byte(`foo`))),
					},
				},
			},
			wantErr: "Unknown blob sha256:invalid",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := new(cache.MockCache)
			c.ApplyGetExpectations(tt.cacheGet)
			c.ApplySetExpectations(tt.cacheSet)

			img := &Image{
				name:       tt.fields.name,
				isFile:     tt.fields.isFile,
				transports: tt.fields.transports,
				cache:      c,
			}
			r, cleanup, err := img.GetBlob(context.Background(), tt.dig)
			if tt.wantErr != "" {
				require.NotNil(t, err, tt.name)
				require.Contains(t, err.Error(), tt.wantErr, tt.name)
				return
			} else {
				require.NoError(t, err, tt.name)
			}
			defer cleanup()

			got, err := ioutil.ReadAll(r)
			require.NoError(t, err, tt.name)
			assert.Equal(t, tt.want, got, tt.name)

			c.AssertExpectations(t)
		})
	}
}
