package cache

import (
	"testing"
	"time"

	"github.com/aquasecurity/fanal/types"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
)

type mockS3Client struct {
	s3iface.S3API
}

func (m *mockS3Client) PutObject(*s3.PutObjectInput) (*s3.PutObjectOutput, error) {
	return &s3.PutObjectOutput{}, nil
}

func (m *mockS3Client) WaitUntilObjectExists(*s3.HeadObjectInput) error {
	return nil

}

func TestS3Cache_PutBlob(t *testing.T) {
	mockSvc := &mockS3Client{}

	type fields struct {
		S3         s3iface.S3API
		Downloader *s3manager.Downloader
		BucketName string
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
			name:   "happy path",
			fields: fields{S3: mockSvc, BucketName: "test"},
			args: args{
				blobID: "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
				blobInfo: types.BlobInfo{
					SchemaVersion: 1,
					OS: &types.OS{
						Family: "alpine",
						Name:   "3.10",
					},
				}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := S3Cache{
				s3:         tt.fields.S3,
				downloader: tt.fields.Downloader,
				bucketName: tt.fields.BucketName,
			}
			if err := cache.PutBlob(tt.args.blobID, tt.args.blobInfo); (err != nil) != tt.wantErr {
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
			name:   "happy path",
			fields: fields{S3: mockSvc, BucketName: "test"},
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
			cache := S3Cache{
				s3:         tt.fields.S3,
				downloader: tt.fields.Downloader,
				bucketName: tt.fields.BucketName,
			}
			if err := cache.PutArtifact(tt.args.artifactID, tt.args.artifactConfig); (err != nil) != tt.wantErr {
				t.Errorf("S3Cache.PutArtifact() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestS3Cache_put(t *testing.T) {
	mockSvc := &mockS3Client{}

	type fields struct {
		S3         s3iface.S3API
		Downloader *s3manager.Downloader
		BucketName string
	}
	type args struct {
		key  string
		body interface{}
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name:   "put",
			fields: fields{S3: mockSvc, BucketName: "test"},
			args:   args{key: "key", body: map[string]interface{}{"key": "val"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := S3Cache{
				s3:         tt.fields.S3,
				downloader: tt.fields.Downloader,
				bucketName: tt.fields.BucketName,
			}
			if err := cache.put(tt.args.key, tt.args.body); (err != nil) != tt.wantErr {
				t.Errorf("S3Cache.put() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
