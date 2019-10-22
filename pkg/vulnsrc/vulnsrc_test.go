package vulnsrc

import (
	"path/filepath"
	"testing"

	"go.uber.org/zap"

	"github.com/aquasecurity/trivy/pkg/db"
	"github.com/aquasecurity/trivy/pkg/git"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils"
	"github.com/aquasecurity/trivy/pkg/vulnsrc/vulnerability"
)

func BenchmarkUpdate(b *testing.B) {
	log.Logger = zap.NewNop().Sugar()
	utils.Quiet = true
	if err := db.Init(); err != nil {
		b.Fatal(err)
	}
	dir := filepath.Join(utils.CacheDir(), "vuln-list")
	if _, err := git.CloneOrPull(repoURL, dir); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()

	b.Run("NVD", func(b *testing.B) {
		dbc := db.Config{}
		for i := 0; i < b.N; i++ {
			if err := dbc.SetVersion(""); err != nil {
				b.Fatal(err)
			}
			if err := Update([]string{vulnerability.Nvd}); err != nil {
				b.Fatal(err)
			}
		}
	})
}
