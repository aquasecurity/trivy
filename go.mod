module github.com/aquasecurity/fanal

go 1.13

require (
	cloud.google.com/go v0.37.4 // indirect
	github.com/GoogleCloudPlatform/docker-credential-gcr v1.5.0
	github.com/aquasecurity/go-dep-parser v0.0.0-20190819075924-ea223f0ef24b
	github.com/aws/aws-sdk-go v1.25.31
	github.com/deckarep/golang-set v1.7.1
	github.com/docker/distribution v2.7.1+incompatible
	github.com/docker/docker v0.0.0-20180924202107-a9c061deec0f
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/genuinetools/reg v0.16.0
	github.com/klauspost/compress v1.9.3
	github.com/knqyf263/go-deb-version v0.0.0-20190517075300-09fca494f03d
	github.com/knqyf263/go-rpmdb v0.0.0-20190501070121-10a1c42a10dc
	github.com/knqyf263/nested v0.0.1
	github.com/kylelemons/godebug v0.0.0-20170820004349-d65d576e9348
	github.com/opencontainers/go-digest v0.0.0-20180430190053-c9281466c8b2
	github.com/pkg/errors v0.8.1
	github.com/simar7/gokv v0.3.2
	github.com/stretchr/testify v1.4.0
	golang.org/x/crypto v0.0.0-20190404164418-38d8ce5564a5
	golang.org/x/xerrors v0.0.0-20190717185122-a985d3407aa7
)

replace github.com/genuinetools/reg => github.com/tomoyamachi/reg v0.16.1-0.20190706172545-2a2250fd7c00
