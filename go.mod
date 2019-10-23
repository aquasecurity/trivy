module github.com/aquasecurity/trivy

go 1.12

require (
	github.com/BurntSushi/toml v0.3.1
	github.com/aquasecurity/fanal v0.0.0-20191015084852-e80236018d26
	github.com/aquasecurity/go-dep-parser v0.0.0-20190819075924-ea223f0ef24b
	github.com/aquasecurity/vuln-list-update v0.0.0-20191016075347-3d158c2bf9a2
	github.com/briandowns/spinner v0.0.0-20190319032542-ac46072a5a91
	github.com/caarlos0/env/v6 v6.0.0
	github.com/emirpasic/gods v1.12.0 // indirect
	github.com/etcd-io/bbolt v1.3.2
	github.com/fatih/color v1.7.0
	github.com/genuinetools/reg v0.16.0
	github.com/gliderlabs/ssh v0.1.3 // indirect
	github.com/knqyf263/go-deb-version v0.0.0-20190517075300-09fca494f03d
	github.com/knqyf263/go-rpm-version v0.0.0-20170716094938-74609b86c936
	github.com/knqyf263/go-version v1.1.1
	github.com/kylelemons/godebug v1.1.0
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/olekukonko/tablewriter v0.0.2-0.20190607075207-195002e6e56a
	github.com/stretchr/testify v1.4.0
	github.com/urfave/cli v1.20.0
	github.com/xanzy/ssh-agent v0.2.1 // indirect
	go.etcd.io/bbolt v1.3.2 // indirect
	go.uber.org/atomic v1.3.2 // indirect
	go.uber.org/multierr v1.1.0 // indirect
	go.uber.org/zap v1.9.1
	golang.org/x/crypto v0.0.0-20190404164418-38d8ce5564a5
	golang.org/x/net v0.0.0-20191014212845-da9a3fd4c582 // indirect
	golang.org/x/sys v0.0.0-20191020152052-9984515f0562 // indirect
	golang.org/x/xerrors v0.0.0-20191011141410-1b5146add898
	gopkg.in/cheggaaa/pb.v1 v1.0.28
	gopkg.in/src-d/go-billy.v4 v4.3.0 // indirect
	gopkg.in/src-d/go-git-fixtures.v3 v3.4.0 // indirect
	gopkg.in/src-d/go-git.v4 v4.10.0
	gopkg.in/yaml.v2 v2.2.4
)

replace github.com/genuinetools/reg => github.com/tomoyamachi/reg v0.16.1-0.20190706172545-2a2250fd7c00
