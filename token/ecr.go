package token

import (
	"context"
	"encoding/base64"
	"strings"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/aws/aws-sdk-go/service/ecr/ecriface"
	"golang.org/x/xerrors"
)

type ECR struct {
	Client ecriface.ECRAPI
}

func NewECR() *ECR {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))
	svc := ecr.New(sess)
	return &ECR{
		Client: svc,
	}
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
