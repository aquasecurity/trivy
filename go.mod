module github.com/knqyf263/trivy

go 1.12

require (
	github.com/BurntSushi/toml v0.3.1
	github.com/briandowns/spinner v0.0.0-20190319032542-ac46072a5a91
	github.com/emirpasic/gods v1.12.0 // indirect
	github.com/etcd-io/bbolt v1.3.2
	github.com/fatih/color v1.7.0
	github.com/genuinetools/reg v0.16.0
	github.com/gliderlabs/ssh v0.1.3 // indirect
	github.com/golang/protobuf v1.3.1 // indirect
	github.com/knqyf263/fanal v0.0.0-20190513061210-e1980f95d1f5
	github.com/knqyf263/go-deb-version v0.0.0-20170509080151-9865fe14d09b
	github.com/knqyf263/go-dep-parser v0.0.0-20190511063217-d5d543bfc261
	github.com/knqyf263/go-rpm-version v0.0.0-20170716094938-74609b86c936
	github.com/knqyf263/go-version v1.1.1
	github.com/mattn/go-colorable v0.1.1 // indirect
	github.com/mattn/go-runewidth v0.0.4 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/olekukonko/tablewriter v0.0.1
	github.com/stretchr/testify v1.3.0 // indirect
	github.com/urfave/cli v1.20.0
	github.com/xanzy/ssh-agent v0.2.1 // indirect
	go.etcd.io/bbolt v1.3.2 // indirect
	go.uber.org/atomic v1.3.2 // indirect
	go.uber.org/multierr v1.1.0 // indirect
	go.uber.org/zap v1.9.1
	golang.org/x/crypto v0.0.0-20190404164418-38d8ce5564a5
	golang.org/x/net v0.0.0-20190404232315-eb5bcb51f2a3 // indirect
	golang.org/x/sys v0.0.0-20190405154228-4b34438f7a67 // indirect
	golang.org/x/xerrors v0.0.0-20190410155217-1f06c39b4373
	gopkg.in/cheggaaa/pb.v1 v1.0.28
	gopkg.in/src-d/go-billy.v4 v4.3.0 // indirect
	gopkg.in/src-d/go-git-fixtures.v3 v3.4.0 // indirect
	gopkg.in/src-d/go-git.v4 v4.10.0
	gopkg.in/yaml.v2 v2.2.2
)

replace github.com/genuinetools/reg => github.com/tomoyamachi/reg v0.16.2-0.20190418055600-c6010b917a55

replace github.com/olekukonko/tablewriter => github.com/knqyf263/tablewriter v0.0.2
