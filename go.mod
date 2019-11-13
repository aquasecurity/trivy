module github.com/aquasecurity/trivy

go 1.13

require (
	github.com/aquasecurity/fanal v0.0.0-20191015084852-e80236018d26
	github.com/aquasecurity/go-dep-parser v0.0.0-20190819075924-ea223f0ef24b
	github.com/aquasecurity/trivy-db v0.0.0-20191101193735-bb56553762c0
	github.com/briandowns/spinner v0.0.0-20190319032542-ac46072a5a91
	github.com/caarlos0/env/v6 v6.0.0
	github.com/genuinetools/reg v0.16.0
	github.com/google/go-github/v28 v28.1.1
	github.com/knqyf263/go-deb-version v0.0.0-20190517075300-09fca494f03d
	github.com/knqyf263/go-rpm-version v0.0.0-20170716094938-74609b86c936
	github.com/knqyf263/go-version v1.1.1
	github.com/kylelemons/godebug v1.1.0
	github.com/olekukonko/tablewriter v0.0.2-0.20190607075207-195002e6e56a
	github.com/stretchr/testify v1.4.0
	github.com/urfave/cli v1.20.0
	go.uber.org/zap v1.9.1
	golang.org/x/crypto v0.0.0-20190404164418-38d8ce5564a5
	golang.org/x/net v0.0.0-20191014212845-da9a3fd4c582 // indirect
	golang.org/x/oauth2 v0.0.0-20190226205417-e64efc72b421
	golang.org/x/sys v0.0.0-20191020152052-9984515f0562 // indirect
	golang.org/x/xerrors v0.0.0-20191011141410-1b5146add898
	gopkg.in/cheggaaa/pb.v1 v1.0.28
	gopkg.in/yaml.v2 v2.2.4 // indirect
	k8s.io/utils v0.0.0-20191010214722-8d271d903fe4
)

replace github.com/genuinetools/reg => github.com/tomoyamachi/reg v0.16.1-0.20190706172545-2a2250fd7c00
