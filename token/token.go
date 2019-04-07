package token

import (
	"context"
	"encoding/base64"
	"strings"

	"github.com/prometheus/common/log"

	"golang.org/x/xerrors"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/docker/docker/api/types"
)

const (
	ecrURL = "amazonaws.com"
	gcrURL = "grc.io"
)

func GetToken(ctx context.Context, auth types.AuthConfig) types.AuthConfig {
	if auth.Username != "" || auth.Password != "" {
		return auth
	}

	var username, password string
	var err error

	switch {
	case strings.HasSuffix(auth.ServerAddress, ecrURL):
		username, password, err = GetECRAuthorizationToken(ctx)
	case strings.HasSuffix(auth.ServerAddress, gcrURL):
		username, password, err = GetGCRAuthorizationToken(ctx)
	}
	if err != nil {
		log.Debugf("failed to get token: %w", err)
	}
	auth.Username = username
	auth.Password = password
	return auth
}

func GetECRAuthorizationToken(ctx context.Context) (username, password string, err error) {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))
	svc := ecr.New(sess)
	input := &ecr.GetAuthorizationTokenInput{}

	result, err := svc.GetAuthorizationTokenWithContext(ctx, input)
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

func GetGCRAuthorizationToken(ctx context.Context) (username, password string, err error) {
	return "", "", nil
}
