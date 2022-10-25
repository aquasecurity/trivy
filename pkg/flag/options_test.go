package flag

import (
	"os"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/types"
)

func Test_getStringSlice(t *testing.T) {
	type env struct {
		key   string
		value string
	}
	tests := []struct {
		name      string
		flag      *Flag
		flagValue interface{}
		env       env
		want      []string
	}{
		{
			name:      "happy path. Empty value",
			flag:      &SecurityChecksFlag,
			flagValue: "",
			want:      nil,
		},
		{
			name:      "happy path. String value",
			flag:      &SecurityChecksFlag,
			flagValue: "license,vuln",
			want:      []string{types.SecurityCheckLicense, types.SecurityCheckVulnerability},
		},
		{
			name:      "happy path. Slice value",
			flag:      &SecurityChecksFlag,
			flagValue: []string{"license", "secret"},
			want:      []string{types.SecurityCheckLicense, types.SecurityCheckSecret},
		},
		{
			name: "happy path. Env value",
			flag: &SecurityChecksFlag,
			env: env{
				key:   "TRIVY_SECURITY_CHECKS",
				value: "rbac,config",
			},
			want: []string{types.SecurityCheckRbac, types.SecurityCheckConfig},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.env.key == "" {
				viper.Set(tt.flag.ConfigName, tt.flagValue)
			} else {
				err := viper.BindEnv(tt.flag.ConfigName, tt.env.key)
				assert.NoError(t, err)

				savedEnvValue := os.Getenv(tt.env.key)
				err = os.Setenv(tt.env.key, tt.env.value)
				assert.NoError(t, err)
				defer os.Setenv(tt.env.key, savedEnvValue)
			}

			sl := getStringSlice(tt.flag)
			assert.Equal(t, tt.want, sl)

			viper.Reset()
		})
	}
}
