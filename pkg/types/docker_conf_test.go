package types

import (
	"os"
	"reflect"
	"testing"

	"github.com/aquasecurity/trivy/pkg/fanal/types"

	"github.com/stretchr/testify/assert"
)

func Test_GetDockerOption(t *testing.T) {
	tests := []struct {
		name     string
		userEnv  string
		passEnv  string
		platform string
		want     types.DockerOption
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
		{name: "num of users higher then password ", userEnv: "user1,user2,user3", passEnv: "pass1,pass2", platform: "platform", want: types.DockerOption{
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
			os.Setenv("TRIVY_USERNAME", tt.userEnv)
			os.Setenv("TRIVY_PASSWORD", tt.passEnv)
			got, _ := GetDockerOption(false, tt.platform)
			assert.True(t, reflect.DeepEqual(got, tt.want))
			// reset
			os.Setenv("TRIVY_USERNAME", "")
			os.Setenv("TRIVY_PASSWORD", "")
		})
	}

}
