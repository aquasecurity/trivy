package config

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"golang.org/x/xerrors"
)

func EndpointResolver(endpoint string) aws.EndpointResolverWithOptionsFunc {
	return aws.EndpointResolverWithOptionsFunc(func(_, reg string, options ...interface{}) (aws.Endpoint, error) {
		return aws.Endpoint{
			PartitionID:   "aws",
			URL:           endpoint,
			SigningRegion: reg,
			Source:        aws.EndpointSourceCustom,
		}, nil
	})
}

func MakeAWSOptions(region, endpoint string) []func(*awsconfig.LoadOptions) error {
	var options []func(*awsconfig.LoadOptions) error

	if region != "" {
		options = append(options, awsconfig.WithRegion(region))
	}

	if endpoint != "" {
		options = append(options, awsconfig.WithEndpointResolverWithOptions(EndpointResolver(endpoint)))
	}

	return options
}

func LoadDefaultAWSConfig(ctx context.Context, region, endpoint string) (aws.Config, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, MakeAWSOptions(region, endpoint)...)
	if err != nil {
		return aws.Config{}, xerrors.Errorf("aws config load error: %w", err)
	}

	if cfg.Region == "" {
		return aws.Config{}, xerrors.New("aws region is required")
	}

	return cfg, nil
}
