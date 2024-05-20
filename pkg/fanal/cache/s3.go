package cache

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

const (
	metadataSchemaVersion = "X-Trivy-Schema-Version"
)

var _ Cache = &S3Cache{}

type s3API interface {
	HeadObject(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	DeleteObject(ctx context.Context, params *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
	ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
}

type S3Cache struct {
	client s3API
	bucket string
	prefix string
}

func NewS3Cache(client s3API, bucket, prefix string) S3Cache {
	return S3Cache{
		client: client,
		bucket: bucket,
		prefix: prefix,
	}
}

func (c S3Cache) artifactKey(artifactID string) string {
	return path.Join(c.prefix, artifactBucket, artifactID)
}

func (c S3Cache) blobKey(blobID string) string {
	return path.Join(c.prefix, blobBucket, blobID)
}

func (c S3Cache) PutArtifact(artifactID string, artifactConfig types.ArtifactInfo) (err error) {
	b, err := json.Marshal(artifactConfig)
	if err != nil {
		return err
	}
	key := c.artifactKey(artifactID)
	params := &s3.PutObjectInput{
		Bucket:        aws.String(c.bucket),
		Key:           aws.String(key),
		ContentLength: aws.Int64(int64(len(b))),
		ContentType:   aws.String("application/json"),
		Body:          bytes.NewReader(b),
		Metadata: map[string]string{
			metadataSchemaVersion: strconv.Itoa(artifactConfig.SchemaVersion),
		},
	}
	if _, err := c.client.PutObject(context.TODO(), params); err != nil {
		return fmt.Errorf("(*s3.Client).PutObject failed for %q: %w", key, err)
	}
	return nil
}

func (c S3Cache) DeleteBlobs(blobIDs []string) error {
	var errs []error
	for _, blobID := range blobIDs {
		key := c.blobKey(blobID)
		if _, err := c.client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
			Bucket: aws.String(c.bucket),
			Key:    aws.String(key),
		}); err != nil {
			errs = append(errs, fmt.Errorf("(*s3.Client).DeleteObject for %q failed: %w", key, err))
		}
	}
	return errors.Join(errs...)
}

func (c S3Cache) PutBlob(blobID string, blobInfo types.BlobInfo) error {
	b, err := json.Marshal(blobInfo)
	if err != nil {
		return err
	}
	key := c.blobKey(blobID)
	params := &s3.PutObjectInput{
		Bucket:        aws.String(c.bucket),
		Key:           aws.String(key),
		ContentLength: aws.Int64(int64(len(b))),
		ContentType:   aws.String("application/json"),
		Body:          bytes.NewReader(b),
		Metadata: map[string]string{
			metadataSchemaVersion: strconv.Itoa(blobInfo.SchemaVersion),
		},
	}
	if _, err := c.client.PutObject(context.TODO(), params); err != nil {
		return fmt.Errorf("(*s3.Client).PutObject failed for %q: %w", key, err)
	}
	return nil
}

func (c S3Cache) GetBlob(blobID string) (types.BlobInfo, error) {
	var info types.BlobInfo
	key := c.blobKey(blobID)
	out, err := c.client.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return info, fmt.Errorf("(*s3.Client).GetObject failed for %q: %w", key, err)
	}
	defer out.Body.Close()
	b, err := io.ReadAll(out.Body)
	if err != nil {
		return info, fmt.Errorf("(*s3.GetObjectOutput).Body.Read failed for %q: %w", key, err)
	}
	if err := json.Unmarshal(b, &info); err != nil {
		return info, fmt.Errorf("json.Unmarshal failed for %q: %w", key, err)
	}
	return info, nil
}

func (c S3Cache) GetArtifact(artifactID string) (types.ArtifactInfo, error) {
	var info types.ArtifactInfo
	key := c.artifactKey(artifactID)
	out, err := c.client.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return info, fmt.Errorf("(*s3.Client).GetObject failed for %q: %w", key, err)
	}
	defer out.Body.Close()
	b, err := io.ReadAll(out.Body)
	if err != nil {
		return info, fmt.Errorf("(*s3.GetObjectOutput).Body.Read failed for %q: %w", key, err)
	}
	if err := json.Unmarshal(b, &info); err != nil {
		return info, fmt.Errorf("json.Unmarshal failed for %q: %w", key, err)
	}
	return info, nil
}

func (c S3Cache) MissingBlobs(artifactID string, blobIDs []string) (bool, []string, error) {
	ctx := context.TODO()
	var missingArtifact bool
	var missingBlobIDs []string
	key := c.artifactKey(artifactID)
	if out, err := c.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(key),
	}); err != nil {
		var nsk *s3types.NoSuchKey
		var nf *s3types.NotFound
		if errors.As(err, &nsk) || errors.As(err, &nf) {
			missingArtifact = true
		} else {
			return true, nil, fmt.Errorf("(*s3.Client).HeadObject failed for %q: %w", key, err)
		}
	} else if out.Metadata != nil && out.Metadata[metadataSchemaVersion] != "" {
		v, err := strconv.Atoi(out.Metadata[metadataSchemaVersion])
		if err != nil {
			return missingArtifact, nil, fmt.Errorf("strconv.Atoi failed for %q: %w", key, err)
		}
		if v != types.ArtifactJSONSchemaVersion {
			missingArtifact = true
		}
	}
	for _, blobID := range blobIDs {
		key := c.blobKey(blobID)
		if out, err := c.client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: aws.String(c.bucket),
			Key:    aws.String(key),
		}); err != nil {
			var nsk *s3types.NoSuchKey
			var nf *s3types.NotFound
			if errors.As(err, &nsk) || errors.As(err, &nf) {
				missingBlobIDs = append(missingBlobIDs, blobID)
				continue
			}
			return missingArtifact, nil, fmt.Errorf("(*s3.Client).HeadObject failed for %q: %w", key, err)
		} else if out.Metadata != nil && out.Metadata[metadataSchemaVersion] != "" {
			v, err := strconv.Atoi(out.Metadata[metadataSchemaVersion])
			if err != nil {
				return missingArtifact, nil, fmt.Errorf("strconv.Atoi failed for %q: %w", key, err)
			}
			if v != types.BlobJSONSchemaVersion {
				missingBlobIDs = append(missingBlobIDs, blobID)
				continue
			}
		}
	}
	return missingArtifact, missingBlobIDs, nil
}

func (c S3Cache) Close() error {
	return nil
}

func (c S3Cache) Clear() error {
	ctx := context.TODO()
	var objs []s3types.Object
	artifactPaginator := s3.NewListObjectsV2Paginator(c.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(c.bucket),
		Prefix: aws.String(path.Join(c.prefix, artifactBucket) + "/"),
	})
	for artifactPaginator.HasMorePages() {
		page, err := artifactPaginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("(*s3.Client).ListObjectsV2 failed: %w", err)
		}
		objs = append(objs, page.Contents...)
	}
	blobPaginator := s3.NewListObjectsV2Paginator(c.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(c.bucket),
		Prefix: aws.String(path.Join(c.prefix, blobBucket) + "/"),
	})
	for blobPaginator.HasMorePages() {
		page, err := blobPaginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("(*s3.Client).ListObjectsV2 failed: %w", err)
		}
		objs = append(objs, page.Contents...)
	}
	var errs []error
	for _, obj := range objs {
		if _, err := c.client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: aws.String(c.bucket),
			Key:    obj.Key,
		}); err != nil {
			errs = append(errs, fmt.Errorf("(*s3.Client).DeleteObject for %q failed: %w", aws.ToString(obj.Key), err))
		}
	}
	return errors.Join(errs...)
}
