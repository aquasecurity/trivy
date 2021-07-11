# Examples

## Custom Policy
### Kubernetes
See [here][k8s].

The custom policy is defined in `user.kubernetes.ID001` package.
You need to pass the package prefix you want to evaluate through `--namespaces` option.
In this case, the package prefix should be `user`, `user.kuberntes`, or `user.kubernetes.ID001`.

### Dockerfile
See [here][dockerfile].

The input will be a dictionary of stages.

#### Single Stage

??? example
    Dockerfile
    ```dockerfile
    FROM foo
    COPY . /
    RUN echo hello
    ```

    Rego Input
    ```json
    {
        "stages": {
            "foo": [
                {
                    "Cmd": "from",
                    "EndLine": 1,
                    "Flags": [],
                    "JSON": false,
                    "Original": "FROM foo",
                    "Stage": 0,
                    "StartLine": 1,
                    "SubCmd": "",
                    "Value": [
                        "foo"
                    ]
                },
                {
                    "Cmd": "copy",
                    "EndLine": 2,
                    "Flags": [],
                    "JSON": false,
                    "Original": "COPY . /",
                    "Stage": 0,
                    "StartLine": 2,
                    "SubCmd": "",
                    "Value": [
                        ".",
                        "/"
                    ]
                },
                {
                    "Cmd": "run",
                    "EndLine": 3,
                    "Flags": [],
                    "JSON": false,
                    "Original": "RUN echo hello",
                    "Stage": 0,
                    "StartLine": 3,
                    "SubCmd": "",
                    "Value": [
                        "echo hello"
                    ]
                }
            ]
        }
    }
    ```

#### Multi Stage

??? example
    Dockerfile
    ```dockerfile
    FROM golang:1.16 AS builder
    WORKDIR /go/src/github.com/alexellis/href-counter/
    RUN go get -d -v golang.org/x/net/html
    COPY app.go .
    RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app .
    
    FROM alpine:latest
    RUN apk --no-cache add ca-certificates \
    && apk add --no-cache bash
    WORKDIR /root/
    COPY --from=builder /go/src/github.com/alexellis/href-counter/app .
    CMD ["./app"]
    ```

    Rego Input
    ```json
    {
        "stages": {
            "alpine:latest": [
                {
                    "Cmd": "from",
                    "EndLine": 7,
                    "Flags": [],
                    "JSON": false,
                    "Original": "FROM alpine:latest",
                    "Stage": 1,
                    "StartLine": 7,
                    "SubCmd": "",
                    "Value": [
                        "alpine:latest"
                    ]
                },
                {
                    "Cmd": "run",
                    "EndLine": 9,
                    "Flags": [],
                    "JSON": false,
                    "Original": "RUN apk --no-cache add ca-certificates     \u0026\u0026 apk add --no-cache bash",
                    "Stage": 1,
                    "StartLine": 8,
                    "SubCmd": "",
                    "Value": [
                        "apk --no-cache add ca-certificates     \u0026\u0026 apk add --no-cache bash"
                    ]
                },
                {
                    "Cmd": "workdir",
                    "EndLine": 10,
                    "Flags": [],
                    "JSON": false,
                    "Original": "WORKDIR /root/",
                    "Stage": 1,
                    "StartLine": 10,
                    "SubCmd": "",
                    "Value": [
                        "/root/"
                    ]
                },
                {
                    "Cmd": "copy",
                    "EndLine": 11,
                    "Flags": [
                        "--from=builder"
                    ],
                    "JSON": false,
                    "Original": "COPY --from=builder /go/src/github.com/alexellis/href-counter/app .",
                    "Stage": 1,
                    "StartLine": 11,
                    "SubCmd": "",
                    "Value": [
                        "/go/src/github.com/alexellis/href-counter/app",
                        "."
                    ]
                },
                {
                    "Cmd": "cmd",
                    "EndLine": 12,
                    "Flags": [],
                    "JSON": true,
                    "Original": "CMD [\"./app\"]",
                    "Stage": 1,
                    "StartLine": 12,
                    "SubCmd": "",
                    "Value": [
                        "./app"
                    ]
                }
            ],
            "golang:1.16 AS builder": [
                {
                    "Cmd": "from",
                    "EndLine": 1,
                    "Flags": [],
                    "JSON": false,
                    "Original": "FROM golang:1.16 AS builder",
                    "Stage": 0,
                    "StartLine": 1,
                    "SubCmd": "",
                    "Value": [
                        "golang:1.16",
                        "AS",
                        "builder"
                    ]
                },
                {
                    "Cmd": "workdir",
                    "EndLine": 2,
                    "Flags": [],
                    "JSON": false,
                    "Original": "WORKDIR /go/src/github.com/alexellis/href-counter/",
                    "Stage": 0,
                    "StartLine": 2,
                    "SubCmd": "",
                    "Value": [
                        "/go/src/github.com/alexellis/href-counter/"
                    ]
                    },
                {
                    "Cmd": "run",
                    "EndLine": 3,
                    "Flags": [],
                    "JSON": false,
                    "Original": "RUN go get -d -v golang.org/x/net/html",
                    "Stage": 0,
                    "StartLine": 3,
                    "SubCmd": "",
                    "Value": [
                        "go get -d -v golang.org/x/net/html"
                    ]
                },
                {
                    "Cmd": "copy",
                    "EndLine": 4,
                    "Flags": [],
                    "JSON": false,
                    "Original": "COPY app.go .",
                    "Stage": 0,
                    "StartLine": 4,
                    "SubCmd": "",
                    "Value": [
                        "app.go",
                        "."
                    ]
                },
                {
                    "Cmd": "run",
                    "EndLine": 5,
                    "Flags": [],
                    "JSON": false,
                    "Original": "RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app .",
                    "Stage": 0,
                    "StartLine": 5,
                    "SubCmd": "",
                    "Value": [
                        "CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app ."
                    ]
                }
            ]
        }
    }
    ```

### Docker Compose
See [here][compose].

Docker Compose uses YAML format for configurations. You can apply your Rego policies to `docker-compose.yml`.

### HCL
See [here][hcl].

Trivy parses HCL files and converts into structured data.

!!! warning
    Terraform HCL files are not supported yet.

### Terraform Plan
See [here][tfplan].

Use the command [terraform show][terraform-show] to convert the Terraform plan into JSON so that OPA can read the plan.

```bash
$ terraform init
$ terraform plan --out tfplan.binary
$ terraform show -json tfplan.binary > tfplan.json
```

For more details, see also [OPA document][opa-terraform].

### Serverless Framework
See [here][serverless].

Server Framework uses YAML format for configurations. You can apply your Rego policies to `serverless.yaml`.

## Custom Data
See [here][data].

## Combined Input
See [here][combine].

## Go Testing
See [here][go-testing].

[k8s]:https://github.com/aquasecurity/trivy/tree/{{ git.commit }}/examples/misconf/custom-policy/kubernetes/
[dockerfile]:https://github.com/aquasecurity/trivy/tree/{{ git.commit }}/examples/misconf/custom-policy/dockerfile/
[compose]:https://github.com/aquasecurity/trivy/tree/{{ git.commit }}/examples/misconf/custom-policy/docker-compose/
[hcl]:https://github.com/aquasecurity/trivy/tree/{{ git.commit }}/examples/misconf/custom-policy/hcl/
[serverless]:https://github.com/aquasecurity/trivy/tree/{{ git.commit }}/examples/misconf/custom-policy/serverless/
[tfplan]:https://github.com/aquasecurity/trivy/tree/{{ git.commit }}/examples/misconf/custom-policy/terraform-plan/
[terraform-show]: https://www.terraform.io/docs/cli/commands/show.html
[opa-terraform]: https://www.openpolicyagent.org/docs/latest/terraform/

[custom]: https://github.com/aquasecurity/trivy/tree/{{ git.commit }}/examples/misconf/custom-policy
[data]: https://github.com/aquasecurity/trivy/tree/{{ git.commit }}/examples/misconf/custom-data
[combine]: https://github.com/aquasecurity/trivy/tree/{{ git.commit }}/examples/misconf/combine
[go-testing]: https://github.com/aquasecurity/trivy/tree/{{ git.commit }}/examples/misconf/go-testing

