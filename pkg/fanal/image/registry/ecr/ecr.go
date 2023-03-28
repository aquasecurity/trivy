package ecr

import (
	"context"
	"encoding/base64"
	"strings"

	"github.com/aquasecurity/trivy/pkg/fanal/types"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/aws/aws-sdk-go/service/ecr/ecriface"
	"golang.org/x/xerrors"
)

const ecrURL = "amazonaws.com"

type ECR struct {
	Client ecriface.ECRAPI
}

func getSession(option types.RemoteOptions) (*session.Session, error) {
	// create custom credential information if option is valid
	if option.AWSSecretKey != "" && option.AWSAccessKey != "" && option.AWSRegion != "" {
		return session.NewSessionWithOptions(
			session.Options{
				Config: aws.Config{
					Region: aws.String(option.AWSRegion),
					Credentials: credentials.NewStaticCredentialsFromCreds(
						credentials.Value{
							AccessKeyID:     option.AWSAccessKey,
							SecretAccessKey: option.AWSSecretKey,
							SessionToken:    option.AWSSessionToken,
						},
					),
				},
			})
	}
	// use shared configuration normally
	return session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	})
}

func (e *ECR) CheckOptions(domain string, option types.RemoteOptions) error {
	if !strings.HasSuffix(domain, ecrURL) {
		return xerrors.Errorf("ECR : %w", types.InvalidURLPattern)
	}
	sess := session.Must(getSession(option))
	svc := ecr.New(sess)
	e.Client = svc
	return nil
}

func (e *ECR) GetCredential(ctx context.Context) (username, password string, err error) {
	input := &ecr.GetAuthorizationTokenInput{}
	result, err := e.Client.GetAuthorizationTokenWithContext(ctx, input)
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
