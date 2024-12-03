package ecr

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	awstypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

type testECRClient interface {
	Options() ecr.Options
}

func TestCheckOptions(t *testing.T) {
	var tests = map[string]struct {
		domain         string
		expectedRegion string
		wantErr        error
	}{
		"InvalidURL": {
			domain:  "alpine:3.9",
			wantErr: types.InvalidURLPattern,
		},
		"InvalidDomain": {
			domain:  "xxx.ecr.ap-northeast-1.not-amazonaws.com",
			wantErr: types.InvalidURLPattern,
		},
		"InvalidSubdomain": {
			domain:  "xxx.s3.ap-northeast-1.amazonaws.com",
			wantErr: types.InvalidURLPattern,
		},
		"NoOption": {
			domain:         "xxx.dkr.ecr.ap-northeast-1.amazonaws.com",
			expectedRegion: "ap-northeast-1",
		},
		"region-1": {
			domain:         "xxx.dkr.ecr.region-1.amazonaws.com",
			expectedRegion: "region-1",
		},
		"region-2": {
			domain:         "xxx.dkr.ecr.region-2.amazonaws.com",
			expectedRegion: "region-2",
		},
		"fips-region-1": {
			domain:         "xxx.dkr.ecr-fips.fips-region.amazonaws.com",
			expectedRegion: "fips-region",
		},
		"cn-region-1": {
			domain:         "xxx.dkr.ecr.region-1.amazonaws.com.cn",
			expectedRegion: "region-1",
		},
		"cn-region-2": {
			domain:         "xxx.dkr.ecr.region-2.amazonaws.com.cn",
			expectedRegion: "region-2",
		},
		"sc2s-region-1": {
			domain:         "xxx.dkr.ecr.sc2s-region.sc2s.sgov.gov",
			expectedRegion: "sc2s-region",
		},
		"c2s-region-1": {
			domain:         "xxx.dkr.ecr.c2s-region.c2s.ic.gov",
			expectedRegion: "c2s-region",
		},
		"invalid-ecr": {
			domain:  "xxx.dkrecr.region-1.amazonaws.com",
			wantErr: types.InvalidURLPattern,
		},
		"invalid-fips": {
			domain:  "xxx.dkr.ecrfips.fips-region.amazonaws.com",
			wantErr: types.InvalidURLPattern,
		},
		"invalid-cn": {
			domain:  "xxx.dkr.ecr.region-2.amazonaws.cn",
			wantErr: types.InvalidURLPattern,
		},
		"invalid-sc2s": {
			domain:  "xxx.dkr.ecr.sc2s-region.sc2s.sgov",
			wantErr: types.InvalidURLPattern,
		},
		"invalid-cs2": {
			domain:  "xxx.dkr.ecr.c2s-region.c2s.ic",
			wantErr: types.InvalidURLPattern,
		},
	}

	for testname, v := range tests {
		a := &ECR{}
		ecrClient, err := a.CheckOptions(v.domain, types.RegistryOptions{})
		if err != nil {
			if !errors.Is(err, v.wantErr) {
				t.Errorf("[%s]\nexpected error based on %v\nactual : %v", testname, v.wantErr, err)
			}
			continue
		}

		client := (ecrClient.(*ECRClient)).Client.(testECRClient)
		require.Equal(t, v.expectedRegion, client.Options().Region)
	}
}

type mockedECR struct {
	Resp ecr.GetAuthorizationTokenOutput
}

func (m mockedECR) GetAuthorizationToken(ctx context.Context, params *ecr.GetAuthorizationTokenInput, optFns ...func(*ecr.Options)) (*ecr.GetAuthorizationTokenOutput, error) {
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
				AuthorizationData: []awstypes.AuthorizationData{
					{AuthorizationToken: aws.String("YXdzOnBhc3N3b3Jk")},
				},
			},
			expectedUser:     "aws",
			expectedPassword: "password",
		},
		{
			Resp: ecr.GetAuthorizationTokenOutput{
				AuthorizationData: []awstypes.AuthorizationData{
					{AuthorizationToken: aws.String("YXdzOnBhc3N3b3JkOmJhZA==")},
				},
			},
			expectedUser:     "aws",
			expectedPassword: "password:bad",
		},
		{
			Resp: ecr.GetAuthorizationTokenOutput{
				AuthorizationData: []awstypes.AuthorizationData{
					{AuthorizationToken: aws.String("YXdzcGFzc3dvcmQ=")},
				},
			},
			expectedUser:     "",
			expectedPassword: "",
		},
	}

	for i, c := range cases {
		e := ECRClient{
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
