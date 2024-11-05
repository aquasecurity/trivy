package ecr

import (
	"context"
	"encoding/base64"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/image/registry/intf"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

type ecrAPI interface {
	GetAuthorizationToken(ctx context.Context, params *ecr.GetAuthorizationTokenInput, optFns ...func(*ecr.Options)) (*ecr.GetAuthorizationTokenOutput, error)
}

type ECR struct {
}

type ECRClient struct {
	Client ecrAPI
}

func getSession(domain, region string, option types.RegistryOptions) (aws.Config, error) {
	// create custom credential information if option is valid
	if option.AWSSecretKey != "" && option.AWSAccessKey != "" && option.AWSRegion != "" {
		if region != option.AWSRegion {
			log.Warnf("The region from AWS_REGION (%s) is being overridden. The region from domain (%s) was used.", option.AWSRegion, domain)
		}
		return config.LoadDefaultConfig(
			context.TODO(),
			config.WithRegion(region),
			config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(option.AWSAccessKey, option.AWSSecretKey, option.AWSSessionToken)),
		)
	}
	return config.LoadDefaultConfig(context.TODO(), config.WithRegion(region))
}

func (e *ECR) CheckOptions(domain string, option types.RegistryOptions) (intf.RegistryClient, error) {
	region := determineRegion(domain)
	if region == "" {
		return nil, xerrors.Errorf("ECR : %w", types.InvalidURLPattern)
	}

	cfg, err := getSession(domain, region, option)
	if err != nil {
		return nil, err
	}

	svc := ecr.NewFromConfig(cfg)
	return &ECRClient{Client: svc}, nil
}

// Endpoints take the form
// <registry-id>.dkr.ecr.<region>.amazonaws.com
// <registry-id>.dkr.ecr-fips.<region>.amazonaws.com
// <registry-id>.dkr.ecr.<region>.amazonaws.com.cn
// <registry-id>.dkr.ecr.<region>.sc2s.sgov.gov
// <registry-id>.dkr.ecr.<region>.c2s.ic.gov
// see
// - https://docs.aws.amazon.com/general/latest/gr/ecr.html
// - https://docs.amazonaws.cn/en_us/aws/latest/userguide/endpoints-arns.html
// - https://github.com/boto/botocore/blob/1.34.51/botocore/data/endpoints.json
var ecrEndpointMatch = regexp.MustCompile(`^[^.]+\.dkr\.ecr(?:-fips)?\.([^.]+)\.(?:amazonaws\.com(?:\.cn)?|sc2s\.sgov\.gov|c2s\.ic\.gov)$`)

func determineRegion(domain string) string {
	matches := ecrEndpointMatch.FindStringSubmatch(domain)
	if matches != nil {
		return matches[1]
	}
	return ""
}

func (e *ECRClient) GetCredential(ctx context.Context) (username, password string, err error) {
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
