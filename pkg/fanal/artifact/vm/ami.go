package vm

import (
	"context"

	"github.com/aquasecurity/trivy/pkg/fanal/types"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/log"
)

type AMI struct {
	*EBS

	imageID string
}

func newAMI(imageID string, storage Storage) (*AMI, error) {
	// TODO: propagate context
	ctx := context.TODO()
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, xerrors.Errorf("aws config load error: %w", err)
	}
	client := ec2.NewFromConfig(cfg)
	output, err := client.DescribeImages(ctx, &ec2.DescribeImagesInput{
		ImageIds: []string{imageID},
	})
	if err != nil {
		return nil, xerrors.Errorf("ec2.DescribeImages: %w", err)
	} else if len(output.Images) == 0 {
		return nil, xerrors.Errorf("%s not found", imageID)
	}

	// Take the first snapshot
	for _, mapping := range output.Images[0].BlockDeviceMappings {
		snapshotID := aws.ToString(mapping.Ebs.SnapshotId)
		if snapshotID == "" {
			continue
		}
		log.Logger.Infof("Snapshot %s found", snapshotID)
		return &AMI{
			EBS:     newEBS(snapshotID, storage),
			imageID: imageID,
		}, nil
	}

	return nil, xerrors.New("no snapshot found")
}

func (a *AMI) Inspect(ctx context.Context) (types.ArtifactReference, error) {
	ref, err := a.EBS.Inspect(ctx)
	if err != nil {
		return types.ArtifactReference{}, err
	}
	ref.Name = a.imageID
	return ref, nil
}
