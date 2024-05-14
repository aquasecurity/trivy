package vm

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"

	"github.com/aquasecurity/trivy/pkg/cloud/aws/config"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/log"
)

type AMI struct {
	*EBS

	imageID string
}

func newAMI(imageID string, storage Storage, region, endpoint string) (*AMI, error) {
	// TODO: propagate context
	ctx := context.TODO()
	cfg, err := config.LoadDefaultAWSConfig(ctx, region, endpoint)
	if err != nil {
		return nil, err
	}
	client := ec2.NewFromConfig(cfg)
	output, err := client.DescribeImages(ctx, &ec2.DescribeImagesInput{
		ImageIds: []string{imageID},
	})
	if err != nil {
		return nil, fmt.Errorf("ec2.DescribeImages: %w", err)
	} else if len(output.Images) == 0 {
		return nil, fmt.Errorf("%s not found", imageID)
	}

	// Take the first snapshot
	for _, mapping := range output.Images[0].BlockDeviceMappings {
		snapshotID := aws.ToString(mapping.Ebs.SnapshotId)
		if snapshotID == "" {
			continue
		}
		log.WithPrefix("ami").Info("Snapshot found", log.String("snapshot_id", snapshotID))
		ebs, err := newEBS(snapshotID, storage, region, endpoint)
		if err != nil {
			return nil, fmt.Errorf("new EBS error: %w", err)
		}
		return &AMI{
			EBS:     ebs,
			imageID: imageID,
		}, nil
	}

	return nil, errors.New("no snapshot found")
}

func (a *AMI) Inspect(ctx context.Context) (artifact.Reference, error) {
	ref, err := a.EBS.Inspect(ctx)
	if err != nil {
		return artifact.Reference{}, err
	}
	ref.Name = a.imageID
	return ref, nil
}
