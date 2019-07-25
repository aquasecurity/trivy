# LAYER builder — — — — — — — — — — — — — — — — — — — — — — —
FROM golang:1.12-alpine AS builder
ADD go.mod go.sum /app/
WORKDIR /app/
RUN apk --no-cache add git upx
RUN go mod download
ADD . /app/
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-X main.version=$(git describe --tags --abbrev=0)" -a -o /trivy cmd/trivy/main.go


# LAYER compress — — — — — — — — — — — — — — — — — — — — — — —
FROM alpine:3.9 AS compress
COPY --from=builder /trivy /usr/local/bin/trivy

RUN set -eux && apk --update --no-cache add \
    upx="3.95-r1" && \
    \
    upx --lzma --best /usr/local/bin/trivy && \
# unit test
    upx -t /usr/local/bin/trivy && \
    trivy --version


# LAYER final — — — — — — — — — — — — — — — — — — — — — — — —
FROM alpine:3.9 AS final
COPY --from=compress /usr/local/bin/trivy /usr/local/bin/trivy

RUN set -eux && apk --update --no-cache add \
    ca-certificates git && \
    rm -rf /var/cache/apk/* && \
    \
    chmod +x /usr/local/bin/trivy

ENTRYPOINT [ "trivy" ]
CMD [ "--help" ]