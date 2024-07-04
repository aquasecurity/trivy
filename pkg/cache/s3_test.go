package cache

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

type mockS3Client struct {
	mockHeadObject    func(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	mockGetObject     func(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	mockPutObject     func(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	mockDeleteObject  func(ctx context.Context, params *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
	mockListObjectsV2 func(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
}

func (m *mockS3Client) HeadObject(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	return m.mockHeadObject(ctx, params, optFns...)
}

func (m *mockS3Client) GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	return m.mockGetObject(ctx, params, optFns...)
}

func (m *mockS3Client) PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	return m.mockPutObject(ctx, params, optFns...)
}

func (m *mockS3Client) DeleteObject(ctx context.Context, params *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	return m.mockDeleteObject(ctx, params, optFns...)
}

func (m *mockS3Client) ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	return m.mockListObjectsV2(ctx, params, optFns...)
}

func TestS3Cache_PutArtifact(t *testing.T) {
	tests := map[string]struct {
		client       func(t *testing.T) s3API
		artifactID   string
		artifactInfo types.ArtifactInfo
		wantErr      string
	}{
		"happy path": {
			client: func(t *testing.T) s3API {
				return &mockS3Client{
					mockPutObject: func(_ context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
						assert.Equal(t, "bucket", aws.ToString(params.Bucket))
						assert.Equal(t, "prefix/artifact/sha256:8652b9f0cb4c0599575e5a003f5906876e10c1ceb2ab9fe1786712dac14a50cf", aws.ToString(params.Key))
						assert.Equal(t, map[string]string{
							metadataSchemaVersion: "1",
						}, params.Metadata)
						b, err := io.ReadAll(params.Body)
						require.NoError(t, err)
						require.True(t, json.Valid(b))
						return &s3.PutObjectOutput{}, nil
					},
				}
			},
			artifactID: "sha256:8652b9f0cb4c0599575e5a003f5906876e10c1ceb2ab9fe1786712dac14a50cf",
			artifactInfo: types.ArtifactInfo{
				SchemaVersion: 1,
				Architecture:  "amd64",
				Created:       time.Date(2020, 11, 14, 0, 20, 4, 0, time.UTC),
				DockerVersion: "19.03.12",
				OS:            "linux",
			},
		},
		"error": {
			client: func(t *testing.T) s3API {
				return &mockS3Client{
					mockPutObject: func(_ context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
						return nil, &s3types.NoSuchBucket{
							Message: params.Bucket,
						}
					},
				}
			},
			artifactID:   "sha256:8652b9f0cb4c0599575e5a003f5906876e10c1ceb2ab9fe1786712dac14a50cf",
			artifactInfo: types.ArtifactInfo{},
			wantErr:      "(*s3.Client).PutObject failed for \"prefix/artifact/sha256:8652b9f0cb4c0599575e5a003f5906876e10c1ceb2ab9fe1786712dac14a50cf\": NoSuchBucket: bucket",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			client := tt.client(t)
			c := NewS3Cache(client, "bucket", "prefix")
			err := c.PutArtifact(tt.artifactID, tt.artifactInfo)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestS3Cache_PutBlob(t *testing.T) {
	tests := map[string]struct {
		client   func(t *testing.T) s3API
		blobID   string
		blobInfo types.BlobInfo
		wantErr  string
	}{
		"happy path": {
			client: func(t *testing.T) s3API {
				return &mockS3Client{
					mockPutObject: func(_ context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
						assert.Equal(t, "bucket", aws.ToString(params.Bucket))
						assert.Equal(t, "prefix/blob/sha256:03901b4a2ea88eeaad62dbe59b072b28b6efa00491962b8741081c5df50c65e0", aws.ToString(params.Key))
						assert.Equal(t, map[string]string{
							metadataSchemaVersion: "2",
						}, params.Metadata)
						b, err := io.ReadAll(params.Body)
						require.NoError(t, err)
						require.True(t, json.Valid(b))
						return &s3.PutObjectOutput{}, nil
					},
				}
			},
			blobID: "sha256:03901b4a2ea88eeaad62dbe59b072b28b6efa00491962b8741081c5df50c65e0",
			blobInfo: types.BlobInfo{
				SchemaVersion: 2,
				Digest:        "sha256:9d48c3bd43c520dc2784e868a780e976b207cbf493eaff8c6596eb871cbd9609",
				DiffID:        "sha256:03901b4a2ea88eeaad62dbe59b072b28b6efa00491962b8741081c5df50c65e0",
				OS: types.OS{
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
		"error": {
			client: func(t *testing.T) s3API {
				return &mockS3Client{
					mockPutObject: func(_ context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
						return nil, &s3types.NoSuchBucket{
							Message: params.Bucket,
						}
					},
				}
			},
			blobID:   "sha256:03901b4a2ea88eeaad62dbe59b072b28b6efa00491962b8741081c5df50c65e0",
			blobInfo: types.BlobInfo{},
			wantErr:  "(*s3.Client).PutObject failed for \"prefix/blob/sha256:03901b4a2ea88eeaad62dbe59b072b28b6efa00491962b8741081c5df50c65e0\": NoSuchBucket: bucket",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			client := tt.client(t)
			c := NewS3Cache(client, "bucket", "prefix")
			err := c.PutBlob(tt.blobID, tt.blobInfo)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestS3Cache_GetArtifact(t *testing.T) {
	info := types.ArtifactInfo{
		SchemaVersion: 1,
		Architecture:  "amd64",
		Created:       time.Date(2020, 11, 14, 0, 20, 4, 0, time.UTC),
		DockerVersion: "19.03.12",
		OS:            "linux",
	}

	tests := map[string]struct {
		client     func(t *testing.T) s3API
		artifactID string
		want       types.ArtifactInfo
		wantErr    string
	}{
		"happy path": {
			client: func(t *testing.T) s3API {
				return &mockS3Client{
					mockGetObject: func(_ context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
						b, err := json.Marshal(info)
						require.NoError(t, err)
						return &s3.GetObjectOutput{
							Body:          io.NopCloser(bytes.NewReader(b)),
							ContentLength: aws.Int64(int64(len(b))),
						}, nil
					},
				}
			},
			artifactID: "sha256:8652b9f0cb4c0599575e5a003f5906876e10c1ceb2ab9fe1786712dac14a50cf",
			want:       info,
		},
		"malformed JSON": {
			client: func(t *testing.T) s3API {
				return &mockS3Client{
					mockGetObject: func(_ context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
						b := []byte("foobar")
						return &s3.GetObjectOutput{
							Body:          io.NopCloser(bytes.NewReader(b)),
							ContentLength: aws.Int64(int64(len(b))),
						}, nil
					},
				}
			},
			artifactID: "sha256:961769676411f082461f9ef46626dd7a2d1e2b2a38e6a44364bcbecf51e66dd4",
			wantErr:    "json.Unmarshal failed for \"prefix/artifact/sha256:961769676411f082461f9ef46626dd7a2d1e2b2a38e6a44364bcbecf51e66dd4\": invalid character 'o' in literal false (expecting 'a')",
		},
		"error": {
			client: func(t *testing.T) s3API {
				return &mockS3Client{
					mockGetObject: func(_ context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
						return nil, &s3types.NoSuchBucket{
							Message: params.Bucket,
						}
					},
				}
			},
			artifactID: "sha256:961769676411f082461f9ef46626dd7a2d1e2b2a38e6a44364bcbecf51e66dd4",
			wantErr:    "(*s3.Client).GetObject failed for \"prefix/artifact/sha256:961769676411f082461f9ef46626dd7a2d1e2b2a38e6a44364bcbecf51e66dd4\": NoSuchBucket: bucket",
		},
		"nonexistent key": {
			client: func(t *testing.T) s3API {
				return &mockS3Client{
					mockGetObject: func(_ context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
						return nil, &s3types.NoSuchKey{
							Message: params.Key,
						}
					},
				}
			},
			artifactID: "sha256:foo",
			wantErr:    "(*s3.Client).GetObject failed for \"prefix/artifact/sha256:foo\": NoSuchKey: prefix/artifact/sha256:foo",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			client := tt.client(t)
			c := NewS3Cache(client, "bucket", "prefix")
			got, err := c.GetArtifact(tt.artifactID)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tt.want, got)
		})
	}
}

func TestS3Cache_GetBlob(t *testing.T) {
	info := types.BlobInfo{
		SchemaVersion: 2,
		Digest:        "sha256:9d48c3bd43c520dc2784e868a780e976b207cbf493eaff8c6596eb871cbd9609",
		DiffID:        "sha256:03901b4a2ea88eeaad62dbe59b072b28b6efa00491962b8741081c5df50c65e0",
		OS: types.OS{
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

	tests := map[string]struct {
		client  func(t *testing.T) s3API
		blobID  string
		want    types.BlobInfo
		wantErr string
	}{
		"happy path": {
			client: func(t *testing.T) s3API {
				return &mockS3Client{
					mockGetObject: func(_ context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
						b, err := json.Marshal(info)
						require.NoError(t, err)
						return &s3.GetObjectOutput{
							Body:          io.NopCloser(bytes.NewReader(b)),
							ContentLength: aws.Int64(int64(len(b))),
						}, nil
					},
				}
			},
			blobID: "sha256:03901b4a2ea88eeaad62dbe59b072b28b6efa00491962b8741081c5df50c65e0",
			want:   info,
		},
		"malformed JSON": {
			client: func(t *testing.T) s3API {
				return &mockS3Client{
					mockGetObject: func(_ context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
						b := []byte("foobar")
						return &s3.GetObjectOutput{
							Body:          io.NopCloser(bytes.NewReader(b)),
							ContentLength: aws.Int64(int64(len(b))),
						}, nil
					},
				}
			},
			blobID:  "sha256:961769676411f082461f9ef46626dd7a2d1e2b2a38e6a44364bcbecf51e66dd4",
			wantErr: "json.Unmarshal failed for \"prefix/blob/sha256:961769676411f082461f9ef46626dd7a2d1e2b2a38e6a44364bcbecf51e66dd4\": invalid character 'o' in literal false (expecting 'a')",
		},
		"error": {
			client: func(t *testing.T) s3API {
				return &mockS3Client{
					mockGetObject: func(_ context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
						return nil, &s3types.NoSuchBucket{
							Message: params.Bucket,
						}
					},
				}
			},
			blobID:  "sha256:961769676411f082461f9ef46626dd7a2d1e2b2a38e6a44364bcbecf51e66dd4",
			wantErr: "(*s3.Client).GetObject failed for \"prefix/blob/sha256:961769676411f082461f9ef46626dd7a2d1e2b2a38e6a44364bcbecf51e66dd4\": NoSuchBucket: bucket",
		},
		"nonexistent key": {
			client: func(t *testing.T) s3API {
				return &mockS3Client{
					mockGetObject: func(_ context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
						return nil, &s3types.NoSuchKey{
							Message: params.Key,
						}
					},
				}
			},
			blobID:  "sha256:foo",
			wantErr: "(*s3.Client).GetObject failed for \"prefix/blob/sha256:foo\": NoSuchKey: prefix/blob/sha256:foo",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			client := tt.client(t)
			c := NewS3Cache(client, "bucket", "prefix")
			got, err := c.GetBlob(tt.blobID)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tt.want, got)
		})
	}
}

func TestS3Cache_MissingBlobs(t *testing.T) {
	tests := map[string]struct {
		client              func(t *testing.T) s3API
		artifactID          string
		blobIDs             []string
		wantMissingArtifact bool
		wantMissingBlobIDs  []string
		wantErr             string
	}{
		"missing both": {
			client: func(t *testing.T) s3API {
				return &mockS3Client{
					mockHeadObject: func(_ context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
						return nil, &s3types.NotFound{
							Message: params.Key,
						}
					},
				}
			},
			artifactID:          "sha256:961769676411f082461f9ef46626dd7a2d1e2b2a38e6a44364bcbecf51e66dd4",
			blobIDs:             []string{"sha256:1b3ee35aacca9866b01dd96e870136266bde18006ac2f0d6eb706c798d1fa3c3"},
			wantMissingArtifact: true,
			wantMissingBlobIDs:  []string{"sha256:1b3ee35aacca9866b01dd96e870136266bde18006ac2f0d6eb706c798d1fa3c3"},
		},
		"missing artifact": {
			client: func(t *testing.T) s3API {
				return &mockS3Client{
					mockHeadObject: func(_ context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
						if strings.HasPrefix(aws.ToString(params.Key), "prefix/artifact/") {
							return nil, &s3types.NotFound{
								Message: params.Key,
							}
						}
						return &s3.HeadObjectOutput{}, nil
					},
				}
			},
			artifactID:          "sha256:961769676411f082461f9ef46626dd7a2d1e2b2a38e6a44364bcbecf51e66dd4",
			blobIDs:             []string{"sha256:03901b4a2ea88eeaad62dbe59b072b28b6efa00491962b8741081c5df50c65e0"},
			wantMissingArtifact: true,
			wantMissingBlobIDs:  []string(nil),
		},
		"missing blobs": {
			client: func(t *testing.T) s3API {
				return &mockS3Client{
					mockHeadObject: func(_ context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
						if strings.HasPrefix(aws.ToString(params.Key), "prefix/blob/") {
							return nil, &s3types.NotFound{
								Message: params.Key,
							}
						}
						return &s3.HeadObjectOutput{}, nil
					},
				}
			},
			artifactID:          "sha256:961769676411f082461f9ef46626dd7a2d1e2b2a38e6a44364bcbecf51e66dd4",
			blobIDs:             []string{"sha256:03901b4a2ea88eeaad62dbe59b072b28b6efa00491962b8741081c5df50c65e0"},
			wantMissingArtifact: false,
			wantMissingBlobIDs:  []string{"sha256:03901b4a2ea88eeaad62dbe59b072b28b6efa00491962b8741081c5df50c65e0"},
		},
		"incorrect blob version": {
			client: func(t *testing.T) s3API {
				return &mockS3Client{
					mockHeadObject: func(_ context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
						if strings.HasPrefix(aws.ToString(params.Key), "prefix/blob/") {
							return &s3.HeadObjectOutput{
								Metadata: map[string]string{
									metadataSchemaVersion: "12345",
								},
							}, nil
						}
						return &s3.HeadObjectOutput{}, nil
					},
				}
			},
			artifactID:          "sha256:961769676411f082461f9ef46626dd7a2d1e2b2a38e6a44364bcbecf51e66dd4",
			blobIDs:             []string{"sha256:03901b4a2ea88eeaad62dbe59b072b28b6efa00491962b8741081c5df50c65e0"},
			wantMissingArtifact: false,
			wantMissingBlobIDs:  []string{"sha256:03901b4a2ea88eeaad62dbe59b072b28b6efa00491962b8741081c5df50c65e0"},
		},
		"incorrect artifact version": {
			client: func(t *testing.T) s3API {
				return &mockS3Client{
					mockHeadObject: func(_ context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
						if strings.HasPrefix(aws.ToString(params.Key), "prefix/artifact/") {
							return &s3.HeadObjectOutput{
								Metadata: map[string]string{
									metadataSchemaVersion: "12345",
								},
							}, nil
						}
						return &s3.HeadObjectOutput{}, nil
					},
				}
			},
			artifactID:          "sha256:961769676411f082461f9ef46626dd7a2d1e2b2a38e6a44364bcbecf51e66dd4",
			blobIDs:             []string{"sha256:03901b4a2ea88eeaad62dbe59b072b28b6efa00491962b8741081c5df50c65e0"},
			wantMissingArtifact: true,
			wantMissingBlobIDs:  []string(nil),
		},
		"error": {
			client: func(t *testing.T) s3API {
				return &mockS3Client{
					mockHeadObject: func(_ context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
						return nil, &s3types.NoSuchBucket{
							Message: params.Bucket,
						}
					},
				}
			},
			artifactID:          "sha256:961769676411f082461f9ef46626dd7a2d1e2b2a38e6a44364bcbecf51e66dd4",
			blobIDs:             []string{"sha256:03901b4a2ea88eeaad62dbe59b072b28b6efa00491962b8741081c5df50c65e0"},
			wantMissingArtifact: false,
			wantMissingBlobIDs:  []string(nil),
			wantErr:             "(*s3.Client).HeadObject failed for \"prefix/artifact/sha256:961769676411f082461f9ef46626dd7a2d1e2b2a38e6a44364bcbecf51e66dd4\": NoSuchBucket: bucket",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			client := tt.client(t)
			c := NewS3Cache(client, "bucket", "prefix")
			missingArtifact, missingBlobIDs, err := c.MissingBlobs(tt.artifactID, tt.blobIDs)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.wantMissingArtifact, missingArtifact)
				require.Equal(t, tt.wantMissingBlobIDs, missingBlobIDs)
			}
		})
	}
}

func TestS3Cache_DeleteBlobs(t *testing.T) {
	info := types.BlobInfo{
		SchemaVersion: 2,
		Digest:        "sha256:9d48c3bd43c520dc2784e868a780e976b207cbf493eaff8c6596eb871cbd9609",
		DiffID:        "sha256:03901b4a2ea88eeaad62dbe59b072b28b6efa00491962b8741081c5df50c65e0",
		OS: types.OS{
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

	tests := map[string]struct {
		client  func(t *testing.T) s3API
		blobIDs []string
		want    types.BlobInfo
		wantErr string
	}{
		"happy path": {
			client: func(t *testing.T) s3API {
				return &mockS3Client{
					mockDeleteObject: func(_ context.Context, params *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
						return &s3.DeleteObjectOutput{}, nil
					},
				}
			},
			blobIDs: []string{"sha256:03901b4a2ea88eeaad62dbe59b072b28b6efa00491962b8741081c5df50c65e0"},
			want:    info,
		},
		"error": {
			client: func(t *testing.T) s3API {
				return &mockS3Client{
					mockDeleteObject: func(_ context.Context, params *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
						return nil, &s3types.NoSuchBucket{
							Message: params.Bucket,
						}
					},
				}
			},
			blobIDs: []string{"(*s3.Client).DeleteObject for \"prefix/blob/sha256:961769676411f082461f9ef46626dd7a2d1e2b2a38e6a44364bcbecf51e66dd4\" failed: NoSuchBucket: bucket"},
			wantErr: "(*s3.Client).DeleteObject for \"prefix/blob/(*s3.Client).DeleteObject for \\\"prefix/blob/sha256:961769676411f082461f9ef46626dd7a2d1e2b2a38e6a44364bcbecf51e66dd4\\\" failed: NoSuchBucket: bucket\" failed: NoSuchBucket: bucket",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			client := tt.client(t)
			c := NewS3Cache(client, "bucket", "prefix")
			err := c.DeleteBlobs(tt.blobIDs)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestS3Cache_Clear(t *testing.T) {
	tests := map[string]struct {
		client  func(t *testing.T) s3API
		wantErr string
	}{
		"happy path": {
			client: func(t *testing.T) s3API {
				return &mockS3Client{
					mockDeleteObject: func(_ context.Context, params *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
						assert.Equal(t, "bucket", aws.ToString(params.Bucket))
						assert.Equal(t, "prefix/artifact/sha256:8652b9f0cb4c0599575e5a003f5906876e10c1ceb2ab9fe1786712dac14a50cf", aws.ToString(params.Key))
						return &s3.DeleteObjectOutput{}, nil
					},
					mockListObjectsV2: func(_ context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
						if strings.HasPrefix(aws.ToString(params.Prefix), "prefix/artifact/") {
							return &s3.ListObjectsV2Output{
								Contents: []s3types.Object{
									{
										Key: aws.String("prefix/artifact/sha256:8652b9f0cb4c0599575e5a003f5906876e10c1ceb2ab9fe1786712dac14a50cf"),
									},
								},
							}, nil
						}
						return &s3.ListObjectsV2Output{}, nil
					},
				}
			},
		},
		"error": {
			client: func(t *testing.T) s3API {
				return &mockS3Client{
					mockListObjectsV2: func(_ context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
						return nil, &s3types.NoSuchBucket{
							Message: params.Bucket,
						}
					},
				}
			},
			wantErr: "(*s3.Client).ListObjectsV2 failed: NoSuchBucket: bucket",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			client := tt.client(t)
			c := NewS3Cache(client, "bucket", "prefix")
			err := c.Clear()
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
