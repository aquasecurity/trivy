FROM alpine:3.22.1
RUN apk --no-cache add ca-certificates git
COPY trivy /usr/local/bin/
COPY contrib/*.tpl contrib/
ENTRYPOINT ["trivy"]
