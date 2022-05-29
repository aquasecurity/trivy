module github.com/aquasecurity/trivy-module-spring4shell

go 1.18

// It points to local Trivy for testing. Normal WASM modules don't need the replace directive.
replace github.com/aquasecurity/trivy => ../../../

require github.com/aquasecurity/trivy v0.0.0-00010101000000-000000000000

require (
	github.com/aquasecurity/fanal v0.0.0-20220529172046-20bc5eb926ed // indirect
	github.com/aquasecurity/go-dep-parser v0.0.0-20220503151658-d316f5cc2cff // indirect
	github.com/aquasecurity/trivy-db v0.0.0-20220521101419-4ae4eb1b87dd // indirect
	github.com/caarlos0/env/v6 v6.9.1 // indirect
	github.com/google/go-containerregistry v0.7.1-0.20211214010025-a65b7844a475 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/mailru/easyjson v0.7.6 // indirect
	golang.org/x/exp v0.0.0-20220407100705-7b9b53b0aca4 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
)
