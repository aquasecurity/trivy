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
    upx && \
    upx --lzma --best /usr/local/bin/trivy && \
# unit test
    upx -t /usr/local/bin/trivy && \
    trivy --version


# LAYER final — — — — — — — — — — — — — — — — — — — — — — — —
FROM alpine:3.9 AS final
COPY --from=compress /usr/local/bin/trivy /usr/local/bin/trivy

RUN set -eux && apk --update --no-cache add \
    ca-certificates git && \
    chmod +x /usr/local/bin/trivy

# best practice credit: https://github.com/opencontainers/image-spec/blob/master/annotations.md
LABEL org.opencontainers.image.authors="Author"                                         \
      org.opencontainers.image.vendors="Vendor"                                         \
      org.opencontainers.image.created="${CREATED_DATE}"                                \
      org.opencontainers.image.revision="${SOURCE_COMMIT}"                              \
      org.opencontainers.image.title="Trivy"                                            \
      org.opencontainers.image.description="Docker image for Trivy"                     \
      org.opencontainers.image.url="https://hub.docker.com/r/0o0o/0o0o/tags/"           \
      org.opencontainers.image.source="https://github.com/0o0o/0o0o"                    \
      org.opencontainers.image.licenses="https://github.com/0o0o/0o0o/LICENSE.md"       \
      org.example.image.user="root"                                                     \
      org.example.image.alpineversion="3.9"                                             \
      org.example.image.schemaversion="1.0"

ENTRYPOINT [ "trivy" ]
CMD [ "--help" ]