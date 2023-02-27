package types

import (
	"reflect"
	"testing"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"golang.org/x/xerrors"

	"github.com/stretchr/testify/assert"
)

func Test_GetDockerOption(t *testing.T) {
	tests := []struct {
		name        string
		userEnv     string
		passEnv     string
		platform    string
		want        types.DockerOption
		expectedErr error
	}{
		{name: "single credential value", userEnv: "user1", passEnv: "pass1", platform: "platform", want: types.DockerOption{
			UserName: "user1",
			Password: "pass1",
			Credentials: []types.Credential{
				{
					UserName: "user1",
					Password: "pass1",
				},
			},
			Platform: "platform",
		},
		},
		{name: "multi credential value", userEnv: "user1,user2", passEnv: "pass1,pass2", platform: "platform", want: types.DockerOption{
			UserName: "user1",
			Password: "pass1",
			Credentials: []types.Credential{
				{
					UserName: "user1",
					Password: "pass1",
				},
				{
					UserName: "user2",
					Password: "pass2",
				},
			},
			Platform: "platform",
		},
		},
		{name: "no credential value", platform: "platform", want: types.DockerOption{
			UserName:    "",
			Password:    "",
			Credentials: []types.Credential{{}},
			Platform:    "platform",
		},
		},
		{name: "num of users higher then password ",
			userEnv:     "user1,user2,user3",
			passEnv:     "pass1,pass2",
			platform:    "platform",
			expectedErr: xerrors.New("the length of usernames and passwords must match"),
			want: types.DockerOption{
				UserName: "user1",
				Password: "pass1",
				Credentials: []types.Credential{
					{
						UserName: "user1",
						Password: "pass1",
					},
					{
						UserName: "user2",
						Password: "pass2",
					},
				},
				Platform: "platform",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("TRIVY_USERNAME", tt.userEnv)
			t.Setenv("TRIVY_PASSWORD", tt.passEnv)
			got, err := GetDockerOption(false, tt.platform)
			if err != nil {
				assert.Equal(t, err.Error(), tt.expectedErr.Error())
			} else {
				assert.True(t, reflect.DeepEqual(got, tt.want))
			}
		})
	}

}
