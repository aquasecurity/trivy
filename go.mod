module github.com/aquasecurity/trivy

go 1.13

require (
	github.com/Masterminds/semver/v3 v3.1.0
	github.com/aquasecurity/bolt-fixtures v0.0.0-20200825112230-c0f517aea2ed
	github.com/aquasecurity/fanal v0.0.0-20200820074632-6de62ef86882
	github.com/aquasecurity/go-dep-parser v0.0.0-20190819075924-ea223f0ef24b
	github.com/aquasecurity/trivy-db v0.0.0-20200826140828-6da6467703aa
	github.com/caarlos0/env/v6 v6.0.0
	github.com/cenkalti/backoff v2.2.1+incompatible
	github.com/cheggaaa/pb/v3 v3.0.3
	github.com/docker/docker v1.4.2-0.20190924003213-a8608b5b67c7
	github.com/docker/go-connections v0.4.0
	github.com/golang/protobuf v1.3.3
	github.com/google/go-containerregistry v0.0.0-20200331213917-3d03ed9b1ca2
	github.com/google/go-github/v28 v28.1.1
	github.com/google/wire v0.3.0
	github.com/knqyf263/go-apk-version v0.0.0-20200609155635-041fdbb8563f
	github.com/knqyf263/go-deb-version v0.0.0-20190517075300-09fca494f03d
	github.com/knqyf263/go-rpm-version v0.0.0-20170716094938-74609b86c936
	github.com/kylelemons/godebug v1.1.0
	github.com/olekukonko/tablewriter v0.0.2-0.20190607075207-195002e6e56a
	github.com/open-policy-agent/opa v0.21.1
	github.com/spf13/afero v1.2.2
	github.com/stretchr/testify v1.6.1
	github.com/testcontainers/testcontainers-go v0.3.1
	github.com/twitchtv/twirp v5.10.1+incompatible
	github.com/urfave/cli/v2 v2.2.0
	go.uber.org/atomic v1.5.1 // indirect
	go.uber.org/multierr v1.4.0 // indirect
	go.uber.org/zap v1.13.0
	golang.org/x/oauth2 v0.0.0-20190604053449-0f29369cfe45
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1
	k8s.io/utils v0.0.0-20191114184206-e782cd3c129f
)
