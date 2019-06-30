package vulnsrc

import (
	"path/filepath"
	"testing"

	"go.uber.org/zap"

	"github.com/knqyf263/trivy/pkg/db"
	"github.com/knqyf263/trivy/pkg/git"
	"github.com/knqyf263/trivy/pkg/log"
	"github.com/knqyf263/trivy/pkg/utils"
	"github.com/knqyf263/trivy/pkg/vulnsrc/vulnerability"
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
		for i := 0; i < b.N; i++ {
			if err := db.SetVersion(""); err != nil {
				b.Fatal(err)
			}
			if err := Update([]string{vulnerability.Nvd}); err != nil {
				b.Fatal(err)
			}
		}
	})
}
