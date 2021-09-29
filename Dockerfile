FROM golang as builder
ADD . /go/trivy
WORKDIR /go/trivy
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-s -w " -a -installsuffix cgo -o /go/bin/trivy ./cmd/trivy
RUN strip /go/bin/trivy
RUN chmod +x /go/bin/trivy

FROM alpine:3.14
RUN apk --no-cache add ca-certificates git
COPY --from=builder /go/bin/trivy /usr/local/bin/trivy
COPY contrib/*.tpl contrib/
ENTRYPOINT ["trivy"]
