FROM alpine:3.18.3
RUN apk --no-cache add ca-certificates git
COPY trivy_linux_amd64 /usr/local/bin/trivy
COPY contrib/*.tpl contrib/
ENTRYPOINT ["trivy"]
