package ecr

import (
	"context"
	"encoding/base64"
	"strings"

	"github.com/aquasecurity/trivy/pkg/fanal/types"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"golang.org/x/xerrors"
)

const ecrURL = "amazonaws.com"

type ecrAPI interface {
	GetAuthorizationToken(ctx context.Context, params *ecr.GetAuthorizationTokenInput, optFns ...func(*ecr.Options)) (*ecr.GetAuthorizationTokenOutput, error)
}

type ECR struct {
	Client ecrAPI
}

func getSession(option types.DockerOption) (aws.Config, error) {
	// create custom credential information if option is valid
	if option.AwsSecretKey != "" && option.AwsAccessKey != "" && option.AwsRegion != "" {
		return config.LoadDefaultConfig(
			context.TODO(),
			config.WithRegion(option.AwsRegion),
			config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(option.AwsAccessKey, option.AwsSecretKey, option.AwsSessionToken)),
		)
	}
	return config.LoadDefaultConfig(context.TODO())
}

func (e *ECR) CheckOptions(domain string, option types.DockerOption) error {
	if !strings.HasSuffix(domain, ecrURL) {
		return xerrors.Errorf("ECR : %w", types.InvalidURLPattern)
	}

	cfg, err := getSession(option)
	if err != nil {
		return err
	}

	svc := ecr.NewFromConfig(cfg)
	e.Client = svc
	return nil
}

func (e *ECR) GetCredential(ctx context.Context) (username, password string, err error) {
	input := &ecr.GetAuthorizationTokenInput{}
	result, err := e.Client.GetAuthorizationToken(ctx, input)
	if err != nil {
		return "", "", xerrors.Errorf("failed to get authorization token: %w", err)
	}
	for _, data := range result.AuthorizationData {
		b, err := base64.StdEncoding.DecodeString(*data.AuthorizationToken)
		if err != nil {
			return "", "", xerrors.Errorf("base64 decode failed: %w", err)
		}
		// e.g. AWS:eyJwYXlsb2...
		split := strings.SplitN(string(b), ":", 2)
		if len(split) == 2 {
			return split[0], split[1], nil
		}
	}
	return "", "", nil
}
