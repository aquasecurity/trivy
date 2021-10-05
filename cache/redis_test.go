package cache_test

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/types"
)

func TestRedisCache_PutArtifact(t *testing.T) {
	type args struct {
		artifactID     string
		artifactConfig types.ArtifactInfo
	}
	tests := []struct {
		name       string
		setupRedis bool
		args       args
		wantKey    string
		wantErr    string
	}{
		{
			name:       "happy path",
			setupRedis: true,
			args: args{
				artifactID: "sha256:8652b9f0cb4c0599575e5a003f5906876e10c1ceb2ab9fe1786712dac14a50cf",
				artifactConfig: types.ArtifactInfo{
					SchemaVersion: 2,
					Architecture:  "amd64",
					Created:       time.Date(2020, 11, 14, 0, 20, 4, 0, time.UTC),
					DockerVersion: "19.03.12",
					OS:            "linux",
				},
			},
			wantKey: "fanal::artifact::sha256:8652b9f0cb4c0599575e5a003f5906876e10c1ceb2ab9fe1786712dac14a50cf",
		},
		{
			name:       "no such host",
			setupRedis: false,
			args: args{
				artifactID:     "sha256:8652b9f0cb4c0599575e5a003f5906876e10c1ceb2ab9fe1786712dac14a50cf",
				artifactConfig: types.ArtifactInfo{},
			},
			wantErr: "unable to store artifact information in Redis cache",
		},
	}

	// Set up Redis test server
	s, err := miniredis.Run()
	require.NoError(t, err)
	defer s.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := s.Addr()
			if !tt.setupRedis {
				addr = "dummy:16379"
			}

			c := cache.NewRedisCache(&redis.Options{
				Addr: addr,
			})

			err = c.PutArtifact(tt.args.artifactID, tt.args.artifactConfig)
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			} else {
				assert.NoError(t, err)
			}

			got, err := s.Get(tt.wantKey)
			require.NoError(t, err)

			want, err := json.Marshal(tt.args.artifactConfig)
			require.NoError(t, err)

			assert.JSONEq(t, string(want), got)
		})
	}
}

func TestRedisCache_PutBlob(t *testing.T) {
	type args struct {
		blobID     string
		blobConfig types.BlobInfo
	}
	tests := []struct {
		name       string
		setupRedis bool
		args       args
		wantKey    string
		wantErr    string
	}{
		{
			name:       "happy path",
			setupRedis: true,
			args: args{
				blobID: "sha256:03901b4a2ea88eeaad62dbe59b072b28b6efa00491962b8741081c5df50c65e0",
				blobConfig: types.BlobInfo{
					SchemaVersion: 2,
					Digest:        "sha256:9d48c3bd43c520dc2784e868a780e976b207cbf493eaff8c6596eb871cbd9609",
					DiffID:        "sha256:03901b4a2ea88eeaad62dbe59b072b28b6efa00491962b8741081c5df50c65e0",
					OS: &types.OS{
						Family: "alpine",
						Name:   "3.10.2",
					},
					PackageInfos: []types.PackageInfo{
						{
							FilePath: "lib/apk/db/installed",
							Packages: []types.Package{
								{
									Name:       "musl",
									Version:    "1.1.22-r3",
									SrcName:    "musl",
									SrcVersion: "1.1.22-r3",
								},
							},
						},
					},
				},
			},
			wantKey: "fanal::blob::sha256:03901b4a2ea88eeaad62dbe59b072b28b6efa00491962b8741081c5df50c65e0",
		},
		{
			name:       "no such host",
			setupRedis: false,
			args: args{
				blobID:     "sha256:03901b4a2ea88eeaad62dbe59b072b28b6efa00491962b8741081c5df50c65e0",
				blobConfig: types.BlobInfo{},
			},
			wantErr: "unable to store blob information in Redis cache",
		},
	}

	// Set up Redis test server
	s, err := miniredis.Run()
	require.NoError(t, err)
	defer s.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := s.Addr()
			if !tt.setupRedis {
				addr = "dummy:16379"
			}

			c := cache.NewRedisCache(&redis.Options{
				Addr: addr,
			})

			err = c.PutBlob(tt.args.blobID, tt.args.blobConfig)
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			} else {
				assert.NoError(t, err)
			}

			got, err := s.Get(tt.wantKey)
			require.NoError(t, err)

			want, err := json.Marshal(tt.args.blobConfig)
			require.NoError(t, err)

			assert.JSONEq(t, string(want), got)
		})
	}
}

func TestRedisCache_GetArtifact(t *testing.T) {
	info := types.ArtifactInfo{
		SchemaVersion: 2,
		Architecture:  "amd64",
		Created:       time.Date(2020, 11, 14, 0, 20, 4, 0, time.UTC),
		DockerVersion: "19.03.12",
		OS:            "linux",
	}

	tests := []struct {
		name       string
		setupRedis bool
		artifactID string
		want       types.ArtifactInfo
		wantErr    string
	}{
		{
			name:       "happy path",
			setupRedis: true,
			artifactID: "sha256:8652b9f0cb4c0599575e5a003f5906876e10c1ceb2ab9fe1786712dac14a50cf",
			want:       info,
		},
		{
			name:       "malformed JSON",
			setupRedis: true,
			artifactID: "sha256:961769676411f082461f9ef46626dd7a2d1e2b2a38e6a44364bcbecf51e66dd4",
			wantErr:    "failed to unmarshal artifact",
		},
		{
			name:       "no such host",
			setupRedis: false,
			artifactID: "sha256:961769676411f082461f9ef46626dd7a2d1e2b2a38e6a44364bcbecf51e66dd4",
			wantErr:    "failed to get artifact from the Redis cache",
		},
		{
			name:       "nonexistent key",
			setupRedis: true,
			artifactID: "sha256:foo",
			wantErr:    "artifact (sha256:foo) is missing in Redis cache",
		},
	}

	// Set up Redis test server
	s, err := miniredis.Run()
	require.NoError(t, err)
	defer s.Close()

	// Set key/value pairs
	b, err := json.Marshal(info)
	require.NoError(t, err)

	s.Set("fanal::artifact::sha256:8652b9f0cb4c0599575e5a003f5906876e10c1ceb2ab9fe1786712dac14a50cf", string(b))
	s.Set("fanal::artifact::sha256:961769676411f082461f9ef46626dd7a2d1e2b2a38e6a44364bcbecf51e66dd4", "foobar")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := s.Addr()
			if !tt.setupRedis {
				addr = "dummy:16379"
			}

			c := cache.NewRedisCache(&redis.Options{
				Addr: addr,
			})

			got, err := c.GetArtifact(tt.artifactID)
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRedisCache_GetBlob(t *testing.T) {
	blobInfo := types.BlobInfo{
		SchemaVersion: 2,
		Digest:        "sha256:9d48c3bd43c520dc2784e868a780e976b207cbf493eaff8c6596eb871cbd9609",
		DiffID:        "sha256:03901b4a2ea88eeaad62dbe59b072b28b6efa00491962b8741081c5df50c65e0",
		OS: &types.OS{
			Family: "alpine",
			Name:   "3.10.2",
		},
		PackageInfos: []types.PackageInfo{
			{
				FilePath: "lib/apk/db/installed",
				Packages: []types.Package{
					{
						Name:       "musl",
						Version:    "1.1.22-r3",
						SrcName:    "musl",
						SrcVersion: "1.1.22-r3",
					},
				},
			},
		},
	}

	tests := []struct {
		name       string
		setupRedis bool
		blobID     string
		want       types.BlobInfo
		wantErr    string
	}{
		{
			name:       "happy path",
			setupRedis: true,
			blobID:     "sha256:03901b4a2ea88eeaad62dbe59b072b28b6efa00491962b8741081c5df50c65e0",
			want:       blobInfo,
		},
		{
			name:       "malformed JSON",
			setupRedis: true,
			blobID:     "sha256:961769676411f082461f9ef46626dd7a2d1e2b2a38e6a44364bcbecf51e66dd4",
			wantErr:    "failed to unmarshal blob",
		},
		{
			name:       "no such host",
			setupRedis: false,
			blobID:     "sha256:961769676411f082461f9ef46626dd7a2d1e2b2a38e6a44364bcbecf51e66dd4",
			wantErr:    "failed to get blob from the Redis cache",
		},
		{
			name:       "nonexistent key",
			setupRedis: true,
			blobID:     "sha256:foo",
			wantErr:    "blob (sha256:foo) is missing in Redis cache",
		},
	}

	// Set up Redis test server
	s, err := miniredis.Run()
	require.NoError(t, err)
	defer s.Close()

	// Set key/value pairs
	b, err := json.Marshal(blobInfo)
	require.NoError(t, err)
	s.Set("fanal::blob::sha256:03901b4a2ea88eeaad62dbe59b072b28b6efa00491962b8741081c5df50c65e0", string(b))
	s.Set("fanal::blob::sha256:961769676411f082461f9ef46626dd7a2d1e2b2a38e6a44364bcbecf51e66dd4", "foobar")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := s.Addr()
			if !tt.setupRedis {
				addr = "dummy:16379"
			}

			c := cache.NewRedisCache(&redis.Options{
				Addr: addr,
			})

			got, err := c.GetBlob(tt.blobID)
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRedisCache_MissingBlobs(t *testing.T) {
	type args struct {
		artifactID string
		blobIDs    []string
	}
	tests := []struct {
		name                string
		setupRedis          bool
		args                args
		wantMissingArtifact bool
		wantMissingBlobIDs  []string
		wantErr             string
	}{
		{
			name:       "missing both",
			setupRedis: true,
			args: args{
				artifactID: "sha256:961769676411f082461f9ef46626dd7a2d1e2b2a38e6a44364bcbecf51e66dd4/1",
				blobIDs:    []string{"sha256:1b3ee35aacca9866b01dd96e870136266bde18006ac2f0d6eb706c798d1fa3c3/11111"},
			},
			wantMissingArtifact: true,
			wantMissingBlobIDs:  []string{"sha256:1b3ee35aacca9866b01dd96e870136266bde18006ac2f0d6eb706c798d1fa3c3/11111"},
		},
		{
			name:       "missing artifact",
			setupRedis: true,
			args: args{
				artifactID: "sha256:961769676411f082461f9ef46626dd7a2d1e2b2a38e6a44364bcbecf51e66dd4/1",
				blobIDs:    []string{"sha256:03901b4a2ea88eeaad62dbe59b072b28b6efa00491962b8741081c5df50c65e0/11111"},
			},
			wantMissingArtifact: true,
		},
		{
			name:       "missing blobs",
			setupRedis: true,
			args: args{
				artifactID: "sha256:8652b9f0cb4c0599575e5a003f5906876e10c1ceb2ab9fe1786712dac14a50cf/1",
				blobIDs:    []string{"sha256:1b3ee35aacca9866b01dd96e870136266bde18006ac2f0d6eb706c798d1fa3c3/11111"},
			},
			wantMissingArtifact: false,
			wantMissingBlobIDs:  []string{"sha256:1b3ee35aacca9866b01dd96e870136266bde18006ac2f0d6eb706c798d1fa3c3/11111"},
		},
		{
			name:       "missing artifact with different schema version",
			setupRedis: true,
			args: args{
				artifactID: "sha256:be4e4bea2c2e15b403bb321562e78ea84b501fb41497472e91ecb41504e8a27c/1",
				blobIDs:    []string{"sha256:03901b4a2ea88eeaad62dbe59b072b28b6efa00491962b8741081c5df50c65e0/11111"},
			},
			wantMissingArtifact: true,
		},
		{
			name:       "missing blobs with different schema version",
			setupRedis: true,
			args: args{
				artifactID: "sha256:8652b9f0cb4c0599575e5a003f5906876e10c1ceb2ab9fe1786712dac14a50cf/1",
				blobIDs:    []string{"sha256:174f5685490326fc0a1c0f5570b8663732189b327007e47ff13d2ca59673db02/11111"},
			},
			wantMissingArtifact: false,
			wantMissingBlobIDs:  []string{"sha256:174f5685490326fc0a1c0f5570b8663732189b327007e47ff13d2ca59673db02/11111"},
		},
		{
			name:       "different analyzer versions",
			setupRedis: true,
			args: args{
				artifactID: "sha256:8652b9f0cb4c0599575e5a003f5906876e10c1ceb2ab9fe1786712dac14a50cf/0",
				blobIDs:    []string{"sha256:03901b4a2ea88eeaad62dbe59b072b28b6efa00491962b8741081c5df50c65e0/11012"},
			},
			wantMissingArtifact: true,
			wantMissingBlobIDs:  []string{"sha256:03901b4a2ea88eeaad62dbe59b072b28b6efa00491962b8741081c5df50c65e0/11012"},
		},
	}

	// Set up Redis test server
	s, err := miniredis.Run()
	require.NoError(t, err)
	defer s.Close()

	s.Set("fanal::artifact::sha256:8652b9f0cb4c0599575e5a003f5906876e10c1ceb2ab9fe1786712dac14a50cf/1",
		fmt.Sprintf("{\"SchemaVersion\": %d}", types.ArtifactJSONSchemaVersion))
	s.Set("fanal::artifact::sha256:be4e4bea2c2e15b403bb321562e78ea84b501fb41497472e91ecb41504e8a27c/1",
		`{"SchemaVersion": 999999}`) // This version should not match the current version
	s.Set("fanal::blob::sha256:03901b4a2ea88eeaad62dbe59b072b28b6efa00491962b8741081c5df50c65e0/11111",
		fmt.Sprintf("{\"SchemaVersion\": %d}", types.BlobJSONSchemaVersion))
	s.Set("fanal::blob::sha256:174f5685490326fc0a1c0f5570b8663732189b327007e47ff13d2ca59673db02/11111",
		`{"SchemaVersion": 999999}`) // This version should not match the current version

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := s.Addr()
			if !tt.setupRedis {
				addr = "dummy:6379"
			}

			c := cache.NewRedisCache(&redis.Options{
				Addr: addr,
			})

			missingArtifact, missingBlobIDs, err := c.MissingBlobs(tt.args.artifactID, tt.args.blobIDs)
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.wantMissingArtifact, missingArtifact)
			assert.Equal(t, tt.wantMissingBlobIDs, missingBlobIDs)
		})
	}
}

func TestRedisCache_Close(t *testing.T) {
	// Set up Redis test server
	s, err := miniredis.Run()
	require.NoError(t, err)
	defer s.Close()

	t.Run("close", func(t *testing.T) {
		c := cache.NewRedisCache(&redis.Options{
			Addr: s.Addr(),
		})
		closeErr := c.Close()
		require.NoError(t, closeErr)
		time.Sleep(3 * time.Second) // give it some time
		assert.Equal(t, 0, s.CurrentConnectionCount(), "The client is disconnected")
	})
}

func TestRedisCache_Clear(t *testing.T) {
	// Set up Redis test server
	s, err := miniredis.Run()
	require.NoError(t, err)
	defer s.Close()

	for i := 0; i < 200; i++ {
		s.Set(fmt.Sprintf("fanal::key%d", i), "value")
	}
	s.Set("foo", "bar")

	t.Run("clear", func(t *testing.T) {
		c := cache.NewRedisCache(&redis.Options{
			Addr: s.Addr(),
		})
		require.NoError(t, c.Clear())
		for i := 0; i < 200; i++ {
			assert.False(t, s.Exists(fmt.Sprintf("fanal::key%d", i)))
		}
		assert.True(t, s.Exists("foo"))
	})
}
