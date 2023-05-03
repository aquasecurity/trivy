FROM alpine:3.17.3
RUN apk --no-cache add bash ca-certificates git
COPY trivy /usr/local/bin/trivy
COPY contrib/*.tpl contrib/
ENTRYPOINT ["trivy"]
