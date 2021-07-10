# Go testing

``` bash
$ go test -v ./...
=== RUN   TestPolicy
=== RUN   TestPolicy/disallowed_ports
--- PASS: TestPolicy (0.09s)
    --- PASS: TestPolicy/disallowed_ports (0.09s)
PASS
ok      github.com/aquasecurity/trivy/examples/misconf/go-testing       0.855s
```