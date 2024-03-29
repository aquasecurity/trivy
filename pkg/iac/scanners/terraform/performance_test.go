package terraform

import (
	"context"
	"fmt"
	"io/fs"
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/rules"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/terraform/executor"
	parser2 "github.com/aquasecurity/trivy/pkg/iac/scanners/terraform/parser"
)

func BenchmarkCalculate(b *testing.B) {

	f, err := createBadBlocks()
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p := parser2.New(f, "", parser2.OptionStopOnHCLError(true))
		if err := p.ParseFS(context.TODO(), "project"); err != nil {
			b.Fatal(err)
		}
		modules, _, err := p.EvaluateAll(context.TODO())
		if err != nil {
			b.Fatal(err)
		}
		_, _, _ = executor.New().Execute(modules)
	}
}

func createBadBlocks() (fs.FS, error) {

	files := make(map[string]string)

	files["/project/main.tf"] = `
module "something" {
	source = "../modules/problem"
}
`

	for _, rule := range rules.GetRegistered() {
		if rule.GetRule().Terraform == nil {
			continue
		}
		for i, bad := range rule.GetRule().Terraform.BadExamples {
			filename := fmt.Sprintf("/modules/problem/%s-%d.tf", rule.GetRule().LongID(), i)
			files[filename] = bad
		}
	}

	f := testutil.CreateFS(&testing.T{}, files)
	return f, nil
}
