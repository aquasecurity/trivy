package cache

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/aquasecurity/fanal/types"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/google/go-containerregistry/pkg/v1"
	"golang.org/x/xerrors"
)

var _ Cache = &S3Cache{}

type S3Cache struct {
	s3         s3iface.S3API
	downloader *s3manager.Downloader
	bucketName string
}

func NewS3Cache(region string, bucketName string) (S3Cache, error) {
	sess, err := session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
		Config:            aws.Config{Region: aws.String(region)},
	})
	if err != nil {
		return S3Cache{}, xerrors.Errorf("failed to load aws credentials: %w", err)
	}

	return S3Cache{
		s3:         s3.New(sess, aws.NewConfig().WithRegion(region)),
		downloader: s3manager.NewDownloader(sess),
		bucketName: bucketName,
	}, nil
}

func (cache S3Cache) PutArtifact(artifactID string, artifactConfig types.ArtifactInfo, opts ...Option) (err error) {
	options := initOpts(opts)
	key := fmt.Sprintf("%s/%s/%s", artifactBucket, options.S3Prefix, artifactID)
	if err := cache.put(key, artifactConfig); err != nil {
		return xerrors.Errorf("unable to store artifact information in cache (%s): %w", artifactID, err)
	}
	return nil
}

func (cache S3Cache) PutBlob(blobID string, blobInfo types.BlobInfo, opts ...Option) error {
	options := initOpts(opts)
	if _, err := v1.NewHash(blobID); err != nil {
		return xerrors.Errorf("invalid diffID (%s): %w", blobID, err)
	}
	key := fmt.Sprintf("%s/%s/%s", blobBucket, options.S3Prefix, blobID)
	if err := cache.put(key, blobInfo); err != nil {
		return xerrors.Errorf("unable to store blob information in cache (%s): %w", blobID, err)
	}
	return nil
}

func (cache S3Cache) put(key string, body interface{}) (err error) {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	params := &s3.PutObjectInput{
		Bucket: aws.String(cache.bucketName),
		Key:    aws.String(key),
		Body:   bytes.NewReader(b),
	}
	_, err = cache.s3.PutObject(params)
	if err != nil {
		return xerrors.Errorf("unable to put object: %w", err)
	}
	headObjectInput := &s3.HeadObjectInput{
		Bucket: aws.String(cache.bucketName),
		Key:    aws.String(key),
	}
	if err = cache.s3.WaitUntilObjectExists(headObjectInput); err != nil {
		return xerrors.Errorf("information was not found in cache: %w", err)
	}
	return nil
}

func (cache S3Cache) GetBlob(blobID string, opts ...Option) (types.BlobInfo, error) {
	var blobInfo types.BlobInfo

	options := initOpts(opts)
	buf := aws.NewWriteAtBuffer([]byte{})
	_, err := cache.downloader.Download(buf, &s3.GetObjectInput{
		Bucket: aws.String(cache.bucketName),
		Key:    aws.String(fmt.Sprintf("%s/%s/%s", blobBucket, options.S3Prefix, blobID)),
	})
	if err != nil {
		return types.BlobInfo{}, xerrors.Errorf("failed to get blob from the cache: %w", err)
	}
	err = json.Unmarshal(buf.Bytes(), &blobInfo)
	if err != nil {
		return types.BlobInfo{}, xerrors.Errorf("JSON unmarshal error: %w", err)
	}

	return blobInfo, nil
}

func (cache S3Cache) GetArtifact(artifactID string, opts ...Option) (types.ArtifactInfo, error) {
	var info types.ArtifactInfo

	options := initOpts(opts)
	buf := aws.NewWriteAtBuffer([]byte{})
	_, err := cache.downloader.Download(buf, &s3.GetObjectInput{
		Bucket: aws.String(cache.bucketName),
		Key:    aws.String(fmt.Sprintf("%s/%s/%s", artifactBucket, options.S3Prefix, artifactID)),
	})
	if err != nil {
		return types.ArtifactInfo{}, xerrors.Errorf("failed to get artifact from the cache: %w", err)
	}
	err = json.Unmarshal(buf.Bytes(), &info)
	if err != nil {
		return types.ArtifactInfo{}, xerrors.Errorf("JSON unmarshal error: %w", err)
	}

	return info, nil
}

func (cache S3Cache) MissingBlobs(artifactID string, blobIDs []string, opts ...Option) (bool, []string, error) {
	var missingArtifact bool
	var missingBlobIDs []string
	for _, blobID := range blobIDs {
		blobInfo, err := cache.GetBlob(blobID, opts...)
		if err != nil {
			// error means cache missed blob info
			missingBlobIDs = append(missingBlobIDs, blobID)
			continue
		}
		if blobInfo.SchemaVersion != types.BlobJSONSchemaVersion {
			missingBlobIDs = append(missingBlobIDs, blobID)
		}
	}
	// get artifact info
	artifactInfo, err := cache.GetArtifact(artifactID, opts...)
	if err != nil {
		// error means cache missed artifact info
		return true, missingBlobIDs, nil
	}
	if artifactInfo.SchemaVersion != types.ArtifactJSONSchemaVersion {
		missingArtifact = true
	}

	return missingArtifact, missingBlobIDs, nil
}

func (cache S3Cache) Close() error {
	return nil
}

func (cache S3Cache) Clear() error {
	return nil
}
