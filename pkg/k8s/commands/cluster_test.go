package commands

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

func TestGetDefaultTolerations(t *testing.T) {
	tolerations := getDefaultTolerations()

	assert.Len(t, tolerations, 2, "should return 2 default tolerations")

	// Check for control-plane toleration
	assert.Contains(t, tolerations, corev1.Toleration{
		Key:      "node-role.kubernetes.io/control-plane",
		Operator: corev1.TolerationOpExists,
		Effect:   corev1.TaintEffectNoSchedule,
	})

	// Check for master toleration (legacy)
	assert.Contains(t, tolerations, corev1.Toleration{
		Key:      "node-role.kubernetes.io/master",
		Operator: corev1.TolerationOpExists,
		Effect:   corev1.TaintEffectNoSchedule,
	})
}
