FROM golang:1.12-alpine AS builder
ADD go.mod go.sum /app/
WORKDIR /app/
RUN apk --no-cache add git upx
RUN go mod download
ADD . /app/
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-X main.version=$(git describe --tags --abbrev=0)" -a -o /trivy cmd/trivy/main.go
RUN upx --lzma --best /trivy

FROM alpine:3.9
RUN apk --no-cache add ca-certificates git
COPY --from=builder /trivy /usr/local/bin/trivy
RUN chmod +x /usr/local/bin/trivy

ENTRYPOINT ["trivy"]
