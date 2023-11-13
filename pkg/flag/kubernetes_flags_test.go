package flag

import (
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

func TestOptionToToleration(t *testing.T) {

	tests := []struct {
		name               string
		tolerationsOptions []string
		want               []corev1.Toleration
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
					TolerationSeconds: lo.ToPtr(int64(3600)),
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := optionToTolerations(tt.tolerationsOptions)
			assert.NoError(t, err)
			assert.Equal(t, got, tt.want)
		})
	}
}
