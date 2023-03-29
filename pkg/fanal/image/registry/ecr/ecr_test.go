package ecr

import (
	"context"
	"errors"
	"testing"

	"github.com/aquasecurity/trivy/pkg/fanal/types"

	"github.com/aws/aws-sdk-go/aws/request"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/aws/aws-sdk-go/service/ecr/ecriface"
)

func TestCheckOptions(t *testing.T) {
	var tests = map[string]struct {
		domain  string
		wantErr error
	}{
		"InvalidURL": {
			domain:  "alpine:3.9",
			wantErr: types.InvalidURLPattern,
		},
		"NoOption": {
			domain: "xxx.ecr.ap-northeast-1.amazonaws.com",
		},
	}

	for testname, v := range tests {
		a := &ECR{}
		err := a.CheckOptions(v.domain, types.RemoteOptions{})
		if err != nil {
			if !errors.Is(err, v.wantErr) {
				t.Errorf("[%s]\nexpected error based on %v\nactual : %v", testname, v.wantErr, err)
			}
			continue
		}
	}
}

type mockedECR struct {
	ecriface.ECRAPI
	Resp ecr.GetAuthorizationTokenOutput
}

func (m mockedECR) GetAuthorizationTokenWithContext(ctx context.Context, input *ecr.GetAuthorizationTokenInput, options ...request.Option) (*ecr.GetAuthorizationTokenOutput, error) {
	return &m.Resp, nil
}

func TestECRGetCredential(t *testing.T) {
	cases := []struct {
		Resp             ecr.GetAuthorizationTokenOutput
		expectedUser     string
		expectedPassword string
	}{
		{
			Resp: ecr.GetAuthorizationTokenOutput{
				AuthorizationData: []*ecr.AuthorizationData{
					{AuthorizationToken: aws.String("YXdzOnBhc3N3b3Jk")},
				},
			},
			expectedUser:     "aws",
			expectedPassword: "password",
		},
		{
			Resp: ecr.GetAuthorizationTokenOutput{
				AuthorizationData: []*ecr.AuthorizationData{
					{AuthorizationToken: aws.String("YXdzOnBhc3N3b3JkOmJhZA==")},
				},
			},
			expectedUser:     "aws",
			expectedPassword: "password:bad",
		},
		{
			Resp: ecr.GetAuthorizationTokenOutput{
				AuthorizationData: []*ecr.AuthorizationData{
					{AuthorizationToken: aws.String("YXdzcGFzc3dvcmQ=")},
				},
			},
			expectedUser:     "",
			expectedPassword: "",
		},
	}

	for i, c := range cases {
		e := ECR{
			Client: mockedECR{Resp: c.Resp},
		}
		username, password, err := e.GetCredential(context.Background())
		if err != nil {
			t.Fatalf("%d, unexpected error", err)
		}
		if username != c.expectedUser {
			t.Fatalf("%d, username: expected %s, got %s", i, c.expectedUser, username)
		}
		if password != c.expectedPassword {
			t.Fatalf("%d, password: expected %s, got %s", i, c.expectedPassword, password)
		}
	}
}
