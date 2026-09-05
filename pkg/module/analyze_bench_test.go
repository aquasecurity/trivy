package module

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/samyfodil/wazy"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
)

func BenchmarkAnalyze(b *testing.B) {
	ctx := context.Background()
	code, err := os.ReadFile("testdata/analyzer/analyzer.wasm")
	if err != nil {
		b.Fatal(err)
	}

	cache := wazy.NewCompilationCache()
	defer cache.Close(ctx)

	plugin, err := newWASMPlugin(ctx, cache, code)
	if err != nil {
		b.Fatal(err)
	}
	defer plugin.Close(ctx)

	content := bytes.NewReader([]byte("package main\n"))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := plugin.Analyze(ctx, analyzer.AnalysisInput{
			FilePath: "foo.go",
			Content:  content,
		})
		if err != nil {
			b.Fatal(err)
		}
	}
}
