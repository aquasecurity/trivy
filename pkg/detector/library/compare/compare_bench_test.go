package compare_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare"
)

// alwaysFalse keeps the benchmark on IsVulnerable's own work rather than
// version-constraint parsing.
func alwaysFalse(_, _ string) (bool, error) { return false, nil }

func TestIsVulnerable_EmptyVersionGuard(t *testing.T) {
	tests := []struct {
		name       string
		vulnerable []string
		patched    []string
		want       bool
	}{
		{"both nil", nil, nil, false},
		{"both empty", []string{}, []string{}, false},
		{"empty string in vulnerable", []string{""}, nil, true},
		{"empty string in patched", nil, []string{""}, true},
		{"empty string in both", []string{""}, []string{""}, true},
		{"empty string alongside a real version", []string{"1.0.0", ""}, nil, true},
		{"no empty string", []string{"1.0.0"}, []string{"2.0.0"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adv := dbTypes.Advisory{
				VulnerableVersions: tt.vulnerable,
				PatchedVersions:    tt.patched,
			}
			assert.Equal(t, tt.want, compare.IsVulnerable("1.0.0", adv, alwaysFalse))
		})
	}
}

func BenchmarkIsVulnerable(b *testing.B) {
	for _, n := range []int{1, 100, 1000} {
		advs := make([]dbTypes.Advisory, n)
		for i := range advs {
			advs[i] = dbTypes.Advisory{
				VulnerableVersions: []string{fmt.Sprintf(">=%d.0.0", i), fmt.Sprintf("<%d.5.0", i)},
				PatchedVersions:    []string{fmt.Sprintf("%d.5.0", i)},
			}
		}
		b.Run(fmt.Sprintf("advisories=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				for _, adv := range advs {
					compare.IsVulnerable("1.0.0", adv, alwaysFalse)
				}
			}
		})
	}
}
