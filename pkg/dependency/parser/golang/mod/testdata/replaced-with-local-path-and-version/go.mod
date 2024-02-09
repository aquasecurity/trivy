module github.com/org/repo

go 1.17

require github.com/aquasecurity/go-dep-parser v0.0.0-20211224170007-df43bca6b6ff

require (
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b // indirect
)

replace golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 => ./xerrors
