module github.com/aquasecurity/fanal

go 1.13

require (
	github.com/GoogleCloudPlatform/docker-credential-gcr v1.5.0
	github.com/Microsoft/go-winio v0.4.15-0.20190919025122-fc70bd9a86b5 // indirect
	github.com/alicebob/miniredis/v2 v2.14.1
	github.com/aquasecurity/go-dep-parser v0.0.0-20201028043324-889d4a92b8e0
	github.com/aquasecurity/testdocker v0.0.0-20210106133225-0b17fe083674
	github.com/aws/aws-sdk-go v1.27.1
	github.com/deckarep/golang-set v1.7.1
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/docker/docker v1.4.2-0.20190924003213-a8608b5b67c7
	github.com/docker/go-connections v0.4.0
	github.com/go-git/go-git/v5 v5.0.0
	github.com/go-redis/redis/v8 v8.4.0
	github.com/google/go-containerregistry v0.0.0-20200331213917-3d03ed9b1ca2
	github.com/hashicorp/go-multierror v1.1.0
	github.com/knqyf263/go-apk-version v0.0.0-20200609155635-041fdbb8563f
	github.com/knqyf263/go-deb-version v0.0.0-20190517075300-09fca494f03d
	github.com/knqyf263/go-rpmdb v0.0.0-20201215100354-a9e3110d8ee1
	github.com/knqyf263/nested v0.0.1
	github.com/kylelemons/godebug v0.0.0-20170820004349-d65d576e9348
	github.com/opencontainers/go-digest v1.0.0-rc1
	github.com/opencontainers/image-spec v1.0.2-0.20190823105129-775207bd45b6
	github.com/saracen/walker v0.0.0-20191201085201-324a081bae7e
	github.com/sosedoff/gitkit v0.2.0
	github.com/stretchr/testify v1.6.1
	github.com/testcontainers/testcontainers-go v0.3.1
	github.com/urfave/cli/v2 v2.2.0
	go.etcd.io/bbolt v1.3.3
	golang.org/x/xerrors v0.0.0-20191204190536-9bdfabe68543
)

// https://github.com/moby/term/issues/15
replace golang.org/x/sys => golang.org/x/sys v0.0.0-20200826173525-f9321e4c35a6
