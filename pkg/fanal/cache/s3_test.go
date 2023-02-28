package cache

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

type mockS3Client struct {
	s3iface.S3API
}

const (
	correctHash = "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7"
)

func (m *mockS3Client) PutObject(*s3.PutObjectInput) (*s3.PutObjectOutput, error) {
	return &s3.PutObjectOutput{}, nil
}

func (m *mockS3Client) HeadObject(*s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
	return &s3.HeadObjectOutput{}, nil
}

func (m *mockS3Client) DeleteBucket(in *s3.DeleteBucketInput) (*s3.DeleteBucketOutput, error) {
	if in != nil && *in.Bucket == blobBucket+"/prefix/"+correctHash {
		return &s3.DeleteBucketOutput{}, nil
	}
	return nil, errors.New("unknown bucket")
}

func TestS3Cache_PutBlob(t *testing.T) {
	mockSvc := &mockS3Client{}

	type fields struct {
		S3         s3iface.S3API
		Downloader *s3manager.Downloader
		BucketName string
		Prefix     string
	}
	type args struct {
		blobID   string
		blobInfo types.BlobInfo
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "happy path",
			fields: fields{
				S3:         mockSvc,
				BucketName: "test",
				Prefix:     "prefix",
			},
			args: args{
				blobID: "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
				blobInfo: types.BlobInfo{
					SchemaVersion: 1,
					OS: types.OS{
						Family: "alpine",
						Name:   "3.10",
					},
				}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewS3Cache(tt.fields.BucketName, tt.fields.Prefix, tt.fields.S3, tt.fields.Downloader)
			if err := c.PutBlob(tt.args.blobID, tt.args.blobInfo); (err != nil) != tt.wantErr {
				t.Errorf("S3Cache.PutBlob() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestS3Cache_PutArtifact(t *testing.T) {
	mockSvc := &mockS3Client{}

	type fields struct {
		S3         s3iface.S3API
		Downloader *s3manager.Downloader
		BucketName string
		Prefix     string
	}
	type args struct {
		artifactID     string
		artifactConfig types.ArtifactInfo
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "happy path",
			fields: fields{
				S3:         mockSvc,
				BucketName: "test",
				Prefix:     "prefix",
			},
			args: args{
				artifactID: "sha256:58701fd185bda36cab0557bb6438661831267aa4a9e0b54211c4d5317a48aff4",
				artifactConfig: types.ArtifactInfo{
					SchemaVersion: 1,
					Architecture:  "amd64",
					Created:       time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC),
					DockerVersion: "18.06.1-ce",
					OS:            "linux",
					HistoryPackages: []types.Package{
						{
							Name:    "musl",
							Version: "1.2.3",
						},
					},
				}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewS3Cache(tt.fields.BucketName, tt.fields.Prefix, tt.fields.S3, tt.fields.Downloader)
			if err := c.PutArtifact(tt.args.artifactID, tt.args.artifactConfig); (err != nil) != tt.wantErr {
				t.Errorf("S3Cache.PutArtifact() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestS3Cache_getIndex(t *testing.T) {
	mockSvc := &mockS3Client{}

	type fields struct {
		S3         s3iface.S3API
		Downloader *s3manager.Downloader
		BucketName string
		Prefix     string
	}
	type args struct {
		key     string
		keyType string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "happy path",
			fields: fields{
				S3:         mockSvc,
				BucketName: "test",
				Prefix:     "prefix",
			},
			args: args{
				key:     "key",
				keyType: "artifactBucket",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewS3Cache(tt.fields.BucketName, tt.fields.Prefix, tt.fields.S3, tt.fields.Downloader)
			if err := c.getIndex(tt.args.key, tt.args.keyType); (err != nil) != tt.wantErr {
				t.Errorf("S3Cache.getIndex() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

type mockS3ClientMissingBlobs struct {
	s3iface.S3API
}

func (m *mockS3ClientMissingBlobs) PutObject(*s3.PutObjectInput) (*s3.PutObjectOutput, error) {
	return &s3.PutObjectOutput{}, nil
}

func (m *mockS3ClientMissingBlobs) HeadObject(*s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
	return &s3.HeadObjectOutput{}, xerrors.Errorf("the object doesn't exist in S3")
}

func TestS3Cache_MissingBlobs(t *testing.T) {
	mockSvc := &mockS3ClientMissingBlobs{}

	type fields struct {
		S3         s3iface.S3API
		Downloader *s3manager.Downloader
		BucketName string
		Prefix     string
	}
	type args struct {
		artifactID             string
		blobIDs                []string
		analyzerVersions       map[string]int
		configAnalyzerVersions map[string]int
	}
	tests := []struct {
		name            string
		fields          fields
		args            args
		want            bool
		wantStringSlice []string
		wantErr         bool
	}{{
		name: "happy path",
		fields: fields{
			S3:         mockSvc,
			BucketName: "test",
			Prefix:     "prefix",
		},
		args: args{
			artifactID: "sha256:58701fd185bda36cab0557bb6438661831267aa4a9e0b54211c4d5317a48aff4/1",
			blobIDs:    []string{"sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7/10011"},
		},
		want:            true,
		wantStringSlice: []string{"sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7/10011"},
		wantErr:         false,
	},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewS3Cache(tt.fields.BucketName, tt.fields.Prefix, tt.fields.S3, tt.fields.Downloader)
			got, got1, err := c.MissingBlobs(tt.args.artifactID, tt.args.blobIDs)
			if (err != nil) != tt.wantErr {
				t.Errorf("S3Cache.MissingBlobs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("S3Cache.MissingBlobs() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.wantStringSlice) {
				t.Errorf("S3Cache.MissingBlobs() got1 = %v, want %v", got1, tt.wantStringSlice)
			}
		})
	}
}

func TestS3Cache_DeleteBlobs(t *testing.T) {
	mockSvc := &mockS3Client{}

	type fields struct {
		S3         s3iface.S3API
		Downloader *s3manager.Downloader
		BucketName string
		Prefix     string
	}
	type args struct {
		blobIDs []string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "happy path",
			fields: fields{
				S3:         mockSvc,
				BucketName: "test",
				Prefix:     "prefix",
			},
			args: args{
				blobIDs: []string{correctHash},
			},
		},
		{
			name: "delete blob with bad ID",
			fields: fields{
				S3:         mockSvc,
				BucketName: "test",
				Prefix:     "prefix",
			},
			args: args{
				blobIDs: []string{"unde"},
			},
			wantErr: true,
		},
		{
			name: "delete blobs with bad ID",
			fields: fields{
				S3:         mockSvc,
				BucketName: "test",
				Prefix:     "prefix",
			},
			args: args{
				blobIDs: []string{correctHash},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewS3Cache(tt.fields.BucketName, tt.fields.Prefix, tt.fields.S3, tt.fields.Downloader)
			if err := c.DeleteBlobs(tt.args.blobIDs); (err != nil) != tt.wantErr {
				t.Errorf("S3Cache.PutBlob() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
