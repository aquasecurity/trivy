package flag

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
)

func TestOptionToToleration(t *testing.T) {

	tests := []struct {
		name               string
		tolerationsOptions []string
		want               []corev1.Toleration
		wantErr            string
	}{
		{
			name:               "no execute",
			tolerationsOptions: []string{"key1=CriticalAddonsOnly:NoExecute:3600"},
			want: []corev1.Toleration{
				{
					Key:               "key1",
					Operator:          "Equal",
					Value:             "CriticalAddonsOnly",
					Effect:            "NoExecute",
					TolerationSeconds: new(int64(3600)),
				},
			},
		},
		{
			name:               "no schedule",
			tolerationsOptions: []string{"key1=CriticalAddonsOnly:NoSchedule"},
			want: []corev1.Toleration{
				{
					Key:      "key1",
					Operator: "Equal",
					Value:    "CriticalAddonsOnly",
					Effect:   "NoSchedule",
				},
			},
		},
		{
			name:               "empty value",
			tolerationsOptions: []string{"node-role.kubernetes.io/control-plane=:NoSchedule"},
			want: []corev1.Toleration{
				{
					Key:      "node-role.kubernetes.io/control-plane",
					Operator: "Exists",
					Effect:   "NoSchedule",
				},
			},
		},
		{
			name:               "key without value",
			tolerationsOptions: []string{"node-role.kubernetes.io/control-plane:NoSchedule"},
			want: []corev1.Toleration{
				{
					Key:      "node-role.kubernetes.io/control-plane",
					Operator: "Exists",
					Effect:   "NoSchedule",
				},
			},
		},
		{
			name:               "key without value with seconds",
			tolerationsOptions: []string{"node.kubernetes.io/unreachable:NoExecute:300"},
			want: []corev1.Toleration{
				{
					Key:               "node.kubernetes.io/unreachable",
					Operator:          "Exists",
					Effect:            "NoExecute",
					TolerationSeconds: new(int64(300)),
				},
			},
		},
		{
			name:               "invalid value",
			tolerationsOptions: []string{"key1=a=b:NoSchedule"},
			wantErr:            `invalid toleration value "a=b"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := optionToTolerations(tt.tolerationsOptions)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
