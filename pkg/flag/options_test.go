package flag

import (
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
			flag:      &ScannersFlag,
			flagValue: "",
			want:      nil,
		},
		{
			name:      "happy path. String value",
			flag:      &ScannersFlag,
			flagValue: "license,vuln",
			want: []string{
				string(types.LicenseScanner),
				string(types.VulnerabilityScanner),
			},
		},
		{
			name: "happy path. Slice value",
			flag: &ScannersFlag,
			flagValue: []string{
				"license",
				"secret",
			},
			want: []string{
				string(types.LicenseScanner),
				string(types.SecretScanner),
			},
		},
		{
			name: "happy path. Env value",
			flag: &ScannersFlag,
			env: env{
				key:   "TRIVY_SECURITY_CHECKS",
				value: "rbac,config",
			},
			want: []string{
				string(types.RBACScanner),
				string(types.MisconfigScanner),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.env.key == "" {
				viper.Set(tt.flag.ConfigName, tt.flagValue)
			} else {
				err := viper.BindEnv(tt.flag.ConfigName, tt.env.key)
				assert.NoError(t, err)

				t.Setenv(tt.env.key, tt.env.value)
			}

			sl := getStringSlice(tt.flag)
			assert.Equal(t, tt.want, sl)

			viper.Reset()
		})
	}
}
